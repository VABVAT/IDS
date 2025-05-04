const mongoose = require("mongoose")

const reportSchema = new mongoose.Schema({
    ip: String,
    issue: String
})

const Report = mongoose.model("Report", reportSchema)

module.exports = Report