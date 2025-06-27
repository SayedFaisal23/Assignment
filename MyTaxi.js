require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const saltRounds = 10;
const { MongoClient, ObjectId } = require('mongodb');
const port = 3000;

const app = express();
app.use(cors());
app.use(express.json());

let db;

// Connect to MongoDB
async function connectToMongoDB() {
    const uri = "mongodb://localhost:27017";
    const client = new MongoClient(uri);

    try {
        await client.connect();
        console.log("Connected to MongoDB!");
        db = client.db("testDB"); // Ensure this matches your DB name
        // Test the connection immediately
        await db.command({ ping: 1 });
        console.log("Database ping successful");
    } catch (err) {
        console.error("MongoDB connection error:", err);
        process.exit(1); // Exit process if cannot connect to DB
    }
}

connectToMongoDB();

app.use(express.static('public'));

// Route to dashboard (optional)
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});

app.get('/', (req, res) => {
  res.send('MyTaxi Backend is running! Try /rides or /users');
});

const PORT = process.env.PORT || 3000; // Azure uses env.PORT
app.listen(PORT, () => console.log(`Running on ${PORT}`));

// Middleware for JWT authentication
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized: No token" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach decoded user info (userId, role)
        next();
    } catch (err) {
        console.error("JWT authentication failed:", err.message);
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
        console.error("Error fetching rides:", err);
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
        console.error("Error fetching ride:", err);
        res.status(500).json({ error: "Failed to fetch ride" });
    }
});

// POST /rides - Create a new ride
app.post('/rides', authenticate, authorize(['user', 'admin']), async (req, res) => {
    try {
        const { origin, destination, fare, passengerId, status, distance } = req.body;
        if (!origin || !destination || !fare || !passengerId || !status || distance === undefined) {
            return res.status(400).json({ error: "Missing required ride fields" });
        }

        const result = await db.collection('rides').insertOne(req.body);
        res.status(201).json({ id: result.insertedId, message: "Ride created" });
    } catch (err) {
        console.error("Error creating ride:", err);
        res.status(400).json({ error: "Invalid Ride Data" });
    }
});

// DELETE /rides/:id - Cancel A Ride
app.delete('/rides/:id', authenticate, authorize(['user', 'admin']), async (req, res) => {
    const id = isValidObjectId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid Ride ID" });

    try {
        const result = await db.collection('rides').deleteOne({ _id: id });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Ride Not Found" });
        res.status(200).json({ deleted: result.deletedCount, message: "Ride cancelled" });
    } catch (err) {
        console.error("Error cancelling ride:", err);
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
        console.error("Error fetching drivers:", err);
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
        console.error("Error fetching driver:", err);
        res.status(500).json({ error: "Failed to fetch driver" });
    }
});

// GET /drivers/filtered - Get drivers (optionally filter by availability and rating)
app.get('/drivers/filtered', async (req, res) => {
    try {
        const query = {};
        if (req.query.isAvailable !== undefined) {
            query.isAvailable = req.query.isAvailable === 'true';
        }
        if (req.query.minRating !== undefined) {
            const minRating = parseFloat(req.query.minRating);
            if (isNaN(minRating)) return res.status(400).json({ error: "minRating must be a number" });
            query.rating = { $gte: minRating };
        }

        const drivers = await db.collection('drivers').find(query).toArray();
        res.json(drivers);
    } catch (err) {
        console.error("Error fetching filtered drivers:", err);
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

        const result = await db.collection('drivers').insertOne(driver);
        res.status(201).json({ id: result.insertedId, message: "Driver added" });
    } catch (err) {
        console.error("Error adding driver:", err);
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
        console.error("Error updating driver status:", err);
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

        // Whitelist other updatable fields for security
        if (otherUpdates.vehicle) updateFields.vehicle = otherUpdates.vehicle;
        if (otherUpdates.license) updateFields.license = otherUpdates.license;
        if (otherUpdates.name) updateFields.name = otherUpdates.name;

        if (Object.keys(updateFields).length === 0) return res.status(400).json({ error: "No valid fields provided for update" });

        const result = await db.collection('drivers').updateOne({ _id: id }, { $set: updateFields });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Driver not found' });

        const updatedDriver = await db.collection('drivers').findOne({ _id: id });
        res.status(200).json({ updatedDriver, message: "Driver updated" });
    } catch (err) {
        console.error("Error updating driver:", err);
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
        console.error("Error deleting driver:", err);
        res.status(500).json({ error: 'Failed to delete driver' });
    }
});

//--------------------------------USER AUTHENTICATION & REGISTRATION--------------------------------//

// POST /users/register - Create a new user with isAdmin boolean
app.post('/users/register', async (req, res) => {
    try {
        if (!db) throw new Error("Database not connected");
        const { name, age, email, password, role, isAdmin } = req.body;
        if (!name || !age || !email || !password || typeof isAdmin !== 'boolean') {
            return res.status(400).json({ error: "Missing required fields or invalid 'isAdmin' type" });
        }

        const existingUser = await db.collection('users').findOne({ email });
        if (existingUser) return res.status(409).json({ error: "User with this email already exists" });

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        let userRole = 'user';
        if (isAdmin) {
            userRole = 'admin';
        } else if (role && typeof role === 'string') {
            userRole = role;
        }

        const user = { name, age, email, password: hashedPassword, role: userRole, isAdmin };
        await db.collection('users').insertOne(user);
        res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: "Registration failed" });
    }
});

// POST /users/login - User login
app.post('/users/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await db.collection('users').findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const tokenRole = user.isAdmin ? 'admin' : user.role;
        const token = jwt.sign(
            { userId: user._id, role: tokenRole },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
        );

        res.status(200).json({ token, role: tokenRole, message: "Login successful" });
    } catch (err) {
        console.error("Login error:", err);
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
        console.error("Error fetching all users (admin):", err);
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
        console.error("Error fetching user (admin):", err);
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
        console.error("Error updating user (admin):", err);
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
        res.status(204).send(); // No content for successful deletion
    } catch (err) {
        console.error("Error deleting user (admin):", err);
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
            {
                $unwind: '$userRides'
            },
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
        console.error("Error generating passenger analytics:", err);
        res.status(500).json({ error: "Failed to generate passenger analytics." });
    }
});

