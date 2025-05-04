const express = require("express");
const cors = require("cors");  
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const Report = require("./models/reports");
const app = express();
app.use(cors());
app.use(express.json());
dotenv.config();  
const mongooseKey = process.env.MONGOOSE_KEY;
mongoose.connect(mongooseKey);

app.post("/alert", async (req, res) => {
    const ip = String(req.body.alert)
    const issue = !req.body.details ? "No details" : String(req.body.details);  
    const newReport = new Report({ ip, issue });
    await newReport.save(); // Save to MongoDB
    console.log("Alert received:", ip, issue);
})

app.listen(3000)
