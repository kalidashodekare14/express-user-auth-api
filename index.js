const express = require('express')
const app = express()
const port = process.env.PORT || 5000
require('dotenv').config()
let cors = require('cors')


// middleware
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))


const { MongoClient, ServerApiVersion } = require('mongodb');
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

        app.post('/user-register', async (req, res) => {
            const userInfo = req.body
            try {
                const result = await userCollection.insertOne(userInfo)
                res.send({ message: 'User registration successful.', result })
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