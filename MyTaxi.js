require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const path = require('path');

const saltRounds = 10;
const port = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET is not set in environment variables.");
    process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

let db;
let client;

// Connect to MongoDB
async function connectToMongoDB() {
    const uri = process.env.MONGODB_URI || "mongodb://localhost:27017";
    client = new MongoClient(uri, {
        serverApi: {
            version: ServerApiVersion.v1,
            strict: true,
            deprecationErrors: true,
        }
    });

    try {
        await client.connect();
        db = client.db("testDB");
        console.log("✅ Successfully connected to MongoDB!");
        await db.command({ ping: 1 });
        console.log("Database ping successful");
    } catch (err) {
        console.error("❌ MongoDB connection failed:", err);
        process.exit(1);
    }
}

connectToMongoDB().then(() => {
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
});

process.on('SIGTERM', async () => {
    if (client) {
        await client.close();
        console.log('MongoDB connection closed');
    }
    process.exit(0);
});

// Health check endpoints
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date() });
});

app.get('/db-health', async (req, res) => {
    try {
        if (!db) throw new Error("Database not initialized");
        await db.command({ ping: 1 });
        res.json({
            status: "healthy",
            db: db.databaseName,
            collections: await db.listCollections().toArray()
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Static files
app.use(express.static('public'));

// Basic routes
app.get('/', (req, res) => {
    res.send('MyTaxi Backend is running! Try /rides or /users');
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});

// Middleware for JWT authentication
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized: No token" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
};

// Middleware for role-based authorization
const authorize = (roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
        return res.status(403).json({ error: "Forbidden: Insufficient permissions" });
    }
    next();
};

// Helper function to validate ObjectId
const isValidObjectId = (id) => {
    try {
        return new ObjectId(id);
    } catch (e) {
        return null;
    }
};

//--------------------------------RIDES ENDPOINTS--------------------------------//

// GET /rides - Fetch All Rides
app.get('/rides', async (req, res) => {
    try {
        const rides = await db.collection('rides').find().toArray();
        res.status(200).json(rides);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch rides" });
    }
});

// GET /rides/:id - Fetch a single ride by ID
app.get('/rides/:id', async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid Ride ID" });

    try {
        const ride = await db.collection('rides').findOne({ _id: id });
        if (!ride) return res.status(404).json({ error: "Ride Not Found" });
        res.status(200).json(ride);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch ride" });
    }
});

// POST /rides - Create a new ride (supports driverId)
app.post('/rides', authenticate, authorize(['user', 'admin']), async (req, res) => {
    try {
        const { origin, destination, fare, passengerId, status, distance, driverId } = req.body;
        if (!origin || !destination || !fare || !passengerId || !status || distance === undefined || !driverId) {
            return res.status(400).json({ error: "Missing required ride fields" });
        }
        const driverObjId = isValidObjectId(driverId);
        if (!driverObjId) return res.status(400).json({ error: "Invalid driverId" });

        const passengerObjId = isValidObjectId(passengerId);
        if (!passengerObjId) return res.status(400).json({ error: "Invalid passengerId" });

        // Check if driver exists and is available
        const driver = await db.collection('drivers').findOne({ _id: driverObjId, isAvailable: true });
        if (!driver) return res.status(400).json({ error: "Driver not available" });

        const ride = { origin, destination, fare, passengerId: passengerObjId, status, distance, driverId: driverObjId };
        const result = await db.collection('rides').insertOne(ride);

        // Set driver as unavailable
        await db.collection('drivers').updateOne({ _id: driverObjId }, { $set: { isAvailable: false } });

        res.status(201).json({ id: result.insertedId, message: "Ride created" });
    } catch (err) {
        res.status(400).json({ error: "Invalid Ride Data" });
    }
});

// DELETE /rides/:id - Cancel A Ride and set driver available
app.delete('/rides/:id', authenticate, authorize(['user', 'admin']), async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid Ride ID" });

    try {
        const ride = await db.collection('rides').findOne({ _id: id });
        if (!ride) return res.status(404).json({ error: "Ride Not Found" });

        // Set driver as available again
        if (ride.driverId) {
            await db.collection('drivers').updateOne({ _id: ride.driverId }, { $set: { isAvailable: true } });
        }

        const result = await db.collection('rides').deleteOne({ _id: id });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Ride Not Found" });
        res.status(200).json({ deleted: result.deletedCount, message: "Ride cancelled" });
    } catch (err) {
        res.status(500).json({ error: "Failed to cancel ride" });
    }
});

//--------------------------------DRIVERS ENDPOINTS--------------------------------//

// GET /drivers - Fetch All Drivers
app.get('/drivers', async (req, res) => {
    try {
        const drivers = await db.collection('drivers').find().toArray();
        res.status(200).json(drivers);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch drivers" });
    }
});

// GET /drivers/:id - Fetch a single driver by ID
app.get('/drivers/:id', async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid Driver ID" });

    try {
        const driver = await db.collection('drivers').findOne({ _id: id });
        if (!driver) return res.status(404).json({ error: "Driver Not Found" });
        res.status(200).json(driver);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch driver" });
    }
});

// GET /drivers/filtered - Get drivers (optionally filter by availability and rating)
app.get('/drivers/filtered', async (req, res) => {
    try {
        const query = {};
        if (req.query.isAvailable !== undefined) {
            query.isAvailable = req.query.isAvailable === true;
        }
        if (req.query.minRating !== undefined) {
            const minRating = parseFloat(req.query.minRating);
            if (isNaN(minRating)) return res.status(400).json({ error: "minRating must be a number" });
            query.rating = { $gte: minRating };
        }

        const drivers = await db.collection('drivers').find(query).toArray();
        res.json(drivers);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch filtered drivers' });
    }
});

// POST /drivers - Add a new driver
app.post('/drivers', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const driver = req.body;
        if (!driver.name || !driver.vehicle) {
            return res.status(400).json({ error: "Missing required driver fields: name, vehicle" });
        }
        if (typeof driver.rating === 'number') {
            driver.rating = Math.round(driver.rating * 10) / 10;
        } else if (driver.rating !== undefined) {
            return res.status(400).json({ error: "Rating must be a number if provided" });
        }
        driver.isAvailable = driver.isAvailable !== undefined ? driver.isAvailable : true;

        const result = await db.collection('drivers').insertOne(driver);
        res.status(201).json({ id: result.insertedId, message: "Driver added" });
    } catch (err) {
        res.status(400).json({ error: 'Invalid Driver Data' });
    }
});

// PATCH /drivers/:id/status - Update driver status
app.patch('/drivers/:id/status', authenticate, authorize(['admin', 'driver']), async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid Driver ID" });
    const { status } = req.body;
    if (!status || typeof status !== 'string') return res.status(400).json({ error: "Status field is required" });

    try {
        const result = await db.collection('drivers').updateOne({ _id: id }, { $set: { status: status } });
        if (result.matchedCount === 0) return res.status(404).json({ error: "Driver Not Found" });
        res.status(200).json({ updated: result.modifiedCount, message: "Driver status updated" });
    } catch (err) {
        res.status(500).json({ error: "Failed to update driver status" });
    }
});

// PATCH /drivers/:id - Modify a driver by ID (e.g., rating update)
app.patch('/drivers/:id', authenticate, authorize(['admin', 'user', 'driver']), async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid Driver ID" });

    try {
        const { rating, ...otherUpdates } = req.body;
        const updateFields = {};

        if (rating !== undefined) {
            if (typeof rating !== 'number') return res.status(400).json({ error: 'Rating must be a number' });
            updateFields.rating = Math.round(rating * 10) / 10;
        }

        if (otherUpdates.vehicle) updateFields.vehicle = otherUpdates.vehicle;
        if (otherUpdates.license) updateFields.license = otherUpdates.license;
        if (otherUpdates.name) updateFields.name = otherUpdates.name;

        if (Object.keys(updateFields).length === 0) return res.status(400).json({ error: "No valid fields provided for update" });

        const result = await db.collection('drivers').updateOne({ _id: id }, { $set: updateFields });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Driver not found' });

        const updatedDriver = await db.collection('drivers').findOne({ _id: id });
        res.status(200).json({ updatedDriver, message: "Driver updated" });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update driver' });
    }
});

// DELETE /drivers/:id - Remove driver by ID (Admin only)
app.delete('/drivers/:id', authenticate, authorize(['admin']), async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid Driver ID" });

    try {
        const result = await db.collection('drivers').deleteOne({ _id: id });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Driver Not Found" });
        res.status(200).json({ deletedCount: result.deletedCount, message: "Driver deleted" });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete driver' });
    }
});

//--------------------------------USER AUTHENTICATION & REGISTRATION--------------------------------//

// POST /users/register - Create a new user with isAdmin boolean
app.post('/users/register', async (req, res) => {
    try {
        if (!db) throw new Error("Database not connected");
        const { name, age, email, password, role, isAdmin, isDriver, vehicle, license } = req.body;
        if (!name || !age || !email || !password || typeof isAdmin !== 'boolean') {
            return res.status(400).json({ error: "Missing required fields or invalid 'isAdmin' type" });
        }

        // Check if user exists
        const existingUser = await db.collection('users').findOne({ email });
        if (existingUser) {
            return res.status(409).json({ error: "User with this email already exists" });
        }

        // Hash password and determine role
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        let userRole = isAdmin ? 'admin' : (role || 'user');

        // Create user
        const user = {
            name,
            age,
            email,
            password: hashedPassword,
            role: userRole,
            isAdmin,
            createdAt: new Date()
        };

        const result = await db.collection('users').insertOne(user);

        // If registering as driver, create driver profile
        if (isDriver) {
            await db.collection('drivers').insertOne({
                name,
                vehicle: vehicle || "",
                license: license || "",
                isAvailable: true,
                userId: result.insertedId
            });
        }

        // Generate token
        const token = jwt.sign(
            { userId: result.insertedId, role: userRole },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
        );

        res.status(201).json({
            message: "User created successfully",
            token,
            userId: result.insertedId
        });
    } catch (err) {
        res.status(500).json({ error: "Registration failed" });
    }
});

app.post('/users/login', async (req, res) => {
    try {
        if (!db) throw new Error("Database not connected");

        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
        }

        const user = await db.collection('users').findOne({ email });
        if (!user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
        );

        res.status(200).json({
            token,
            role: user.role,
            userId: user._id,
            message: "Login successful"
        });
    } catch (err) {
        res.status(500).json({ error: "Login failed" });
    }
});

//--------------------------------ADMIN USER MANAGEMENT ENDPOINTS--------------------------------//

// GET /admin/users - Fetch All users (Admin only)
app.get('/admin/users', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const users = await db.collection('users').find({}, { projection: { password: 0 } }).toArray();
        res.status(200).json(users);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch users" });
    }
});

// GET /admin/users/:id - Fetch a single user by ID (Admin only)
app.get('/admin/users/:id', authenticate, authorize(['admin']), async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid User ID" });

    try {
        const user = await db.collection('users').findOne({ _id: id }, { projection: { password: 0 } });
        if (!user) return res.status(404).json({ error: "User Not Found" });
        res.status(200).json(user);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch user" });
    }
});

// PATCH /admin/users/:id - Update user details (Admin only)
app.patch('/admin/users/:id', authenticate, authorize(['admin']), async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid User ID" });

    try {
        const updates = req.body;
        if (updates.password) return res.status(400).json({ error: "Password cannot be updated directly" });
        if (updates.isAdmin !== undefined && typeof updates.isAdmin !== 'boolean') {
            return res.status(400).json({ error: "'isAdmin' must be a boolean" });
        }

        // Handle role logic based on isAdmin
        if (updates.isAdmin === true) {
            updates.role = 'admin';
        } else if (updates.isAdmin === false && updates.role === undefined) {
            const currentUser = await db.collection('users').findOne({ _id: id });
            if (!currentUser) return res.status(404).json({ error: "User Not Found" });
            updates.role = (currentUser.role === 'admin') ? 'user' : currentUser.role;
        }

        const result = await db.collection('users').updateOne({ _id: id }, { $set: updates });
        if (result.matchedCount === 0) return res.status(404).json({ error: "User Not Found" });

        const updatedUser = await db.collection('users').findOne({ _id: id }, { projection: { password: 0 } });
        res.status(200).json({ updatedUser, message: "User updated" });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// DELETE /admin/users/:id - Admin only delete user
app.delete('/admin/users/:id', authenticate, authorize(['admin']), async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid User ID" });

    try {
        const result = await db.collection('users').deleteOne({ _id: id });
        if (result.deletedCount === 0) return res.status(404).json({ error: "User Not Found" });
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: "Failed to delete user" });
    }
});

//--------------------------------ANALYTICS ENDPOINTS--------------------------------//

// GET /analytics/passengers - Calculate statistics of passengers
app.get('/analytics/passengers', async (req, res) => {
    try {
        const pipeline = [
            {
                $lookup: {
                    from: 'rides',
                    localField: '_id',
                    foreignField: 'passengerId',
                    as: 'userRides'
                }
            },
            { $unwind: '$userRides' },
            {
                $group: {
                    _id: '$_id',
                    name: { $first: '$name' },
                    totalRides: { $sum: 1 },
                    totalFare: { $sum: '$userRides.fare' },
                    totalDistance: { $sum: '$userRides.distance' }
                }
            },
            {
                $project: {
                    _id: 0,
                    name: 1,
                    totalRides: 1,
                    totalFare: 1,
                    avgDistance: {
                        $cond: {
                            if: { $gt: ['$totalRides', 0] },
                            then: { $divide: ['$totalDistance', '$totalRides'] },
                            else: 0
                        }
                    }
                }
            }
        ];

        const passengerAnalytics = await db.collection('users').aggregate(pipeline).toArray();
        res.status(200).json(passengerAnalytics);

    } catch (err) {
        res.status(500).json({ error: "Failed to generate passenger analytics." });
    }
});

app.get('/test-connection', async (req, res) => {
    try {
        if (!db) throw new Error("Database not initialized");
        await db.command({ ping: 1 });
        res.json({ status: "OK", message: "Database connected!" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});