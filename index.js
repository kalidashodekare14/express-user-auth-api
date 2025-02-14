const express = require('express')
const app = express()
const port = process.env.PORT || 5000
require('dotenv').config()
let cors = require('cors')
const bcrypt = require('bcrypt')
var jwt = require('jsonwebtoken');



// middleware
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.rxjug.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        // database collection
        const userCollection = client.db('express-user-auth-api').collection('users')

        // middleware
        const authenticationToken = (req, res, next) => {
            const token = req.header('Authorization')?.split(" ")[1]
            if (!token) {
                return res.status(401).json({ message: "Unauthorized token" })
            }
            jwt.verify(token, process.env.SECRET_KEY, (error, decoded) => {
                if (error) {
                    return res.status(403).json({ message: "Forbidden token" })
                }
                req.user = decoded
                next()
            })
        }

        // user registration
        app.post('/user-register', async (req, res) => {
            const userInfo = req.body
            const hashPassword = bcrypt.hashSync(userInfo.password, 14)
            try {
                const result = await userCollection.insertOne({ ...userInfo, password: hashPassword })
                res.send({ message: 'User registration successful.', result })
            } catch (error) {
                console.log(error)
            }
        })

        // user login and jwt token set up
        app.post('/login', async (req, res) => {
            try {

                const { email, password } = req.body

                console.log('check info', email)

                const emailMatched = await userCollection.findOne({ email })

                if (!emailMatched) {
                    return res.status(400).json({ message: 'Invail email or password' })
                }

                const passwordCompare = await bcrypt.compare(password, emailMatched.password)

                if (!passwordCompare) {
                    return res.status(400).json({ message: 'Invail Password' })
                }

                const token = jwt.sign({ id: emailMatched._id, email: emailMatched.email }, process.env.SECRET_KEY, { expiresIn: '1h' });

                res.json({ token, emailMatched })

            } catch (error) {
                console.log(error)
            }
        })

        // user search
        app.get('/user-search', authenticationToken, async (req, res) => {
            try {
                const { email, username } = req.body
                const userQuery = await userCollection.findOne({
                    $or: [
                        { email: email },
                        { username: username }
                    ]
                })

                if(!userQuery){
                    return res.status(404).json({ message: "User not found" })
                }

                if (req.user.id !== userQuery._id.toString()) {
                    return res.status(403).json({ message: "Forbidden: You are not allowed to access this user's data" })
                }

                res.json(userQuery)
            } catch (error) {
                console.log(error)
            }
        })


        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('Express User Auth Api Server Is Running')
})

app.listen(port, () => {
    console.log(`Express User Auth Api Server is running port:${port}`)
})