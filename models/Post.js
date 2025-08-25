const mongoose = require("mongoose");

const postSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true,
    },
    content: {
        type: String,
        required: true,
    },
    description: {
        type: String,
    },
    language: {
        type: String,
        enum: ["te", "en"],
        required: true,
    },
    genres: {
        type: [String],
        required: true,
        enum: [
            //poems
            "Tragic",
            "Satirical",
            "Romantic",
            "Philosophical",
            "Absurdist",
            "Utopian / Dystopian",
            "Psychological / Introspective",
            "Dark / Noir",
            "Mystical / Spiritual",
            "Whimsical / Surreal",
            "Revolutionary / Liberation Narrative",
            "Resistance & Rebellion Narrative",
            "Post-Colonial Narrative",
            "Social Justice / Civil Rights Theme",
            "Spiritual Liberation / Inner Awakening",
            //stories and essays
            "Social Fiction",
            "Science Fiction",
            "Fantasy",
            "Historical Fiction",
            "Political Fiction",
            "Magical Realism",
            "Speculative Fiction",
            "Mythopoeia (Myth-Making Fiction)",
            "Cyberpunk / Post-cyberpunk",
            "Timedependent Imagination",
            "Revolutionary / Liberation Narrative",
            "Resistance & Rebellion Narrative",
            "Post-Colonial Narrative",
            "Social Justice / Civil Rights Theme",
            "Spiritual Liberation / Inner Awakening",
        ],
    },
    type: {
        type: String,
        enum: ["poem", "story", "essay"],
        required: true,
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
    },
    comments: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Comment",
        },
    ],
    likes: [{
  type: mongoose.Schema.Types.ObjectId,
  ref: "User"
}],
    createdAt: {
        type: Date,
        default: Date.now,
    },
    
});

module.exports = mongoose.model("Post", postSchema);
