const mongoose = require("mongoose");

const Competitions = new mongoose.Schema(
  {
    name:        { type: String, required: true },
    phone:       { type: String, required: true },
    college:     { type: String, required: true },
    email:       { type: String, required: true, lowercase: true, trim: true },
    roll:        { type: String, required: true }, // No unique constraint
    content:     { type: String, required: true },
    description: { type: String, required: true },
    isSubmitted: { type: Boolean, default: false },

    // ✅ Add author field to track the user who submitted
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User", // Adjust to your actual user model name
      required: true
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("CompetitionSubmission", Competitions);
