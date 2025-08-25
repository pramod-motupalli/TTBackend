require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("./models/User");
const Post = require("./models/Post");
const Comment = require("./models/Comments");
const admin = require("./firebase"); // Firebase Admin initialized here
const authRoutes = require("./routes/authRoutes");
const YouTubeUpload = require('./models/YoutubeUpload');
const Competition = require("./models/Competitions");
const { GoogleGenAI } = require("@google/genai");

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

const app = express();
app.use(cors());
app.use(express.json());
app.use("/", authRoutes);
// MongoDB Connection
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB connected"))
    .catch((err) => {
        console.error("❌ MongoDB connection error:", err);
        process.exit(1);
    });

const auth = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select("-password");

        if (!user)
            return res.status(401).json({ message: "User no longer exists" });

        req.user = user;
        next();
    } catch (err) {
        console.error("Auth error:", err.message);
        return res.status(401).json({ message: "Invalid or expired token" });
    }
};

//manual-signup

app.post("/signup", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res
            .status(400)
            .json({ message: "Email and password are required" });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }
        const newUser = new User({ email, password: password });
        await newUser.save();

        res.status(201).json({ message: "Signup successful" });
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

//manual-login

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    console.log("🔐 Login attempt with:", { email, password });

    if (!email || !password) {
        console.log("❌ Missing email or password");
        return res
            .status(400)
            .json({ message: "Email and password are required" });
    }

    try {
        const user = await User.findOne({ email }).select("+password"); // <-- add this if password is select: false in schema
        console.log("📦 User fetched from DB:", user);

        if (!user || !user.password) {
            console.log("❌ No user found or password missing");
            return res
                .status(400)
                .json({ message: "Invalid email or password" });
        }

        // Compare passwords securely
        const isMatch = await bcrypt.compare(password, user.password);
        console.log("🔍 Password match:", isMatch);

        if (!isMatch) {
            console.log("❌ Passwords do not match");
            return res
                .status(400)
                .json({ message: "Invalid email or password" });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET || "your_jwt_secret_key"
        );
        console.log("✅ JWT Token generated:", token);
        const isVisited = user.isVisited;
        res.json({
            message: "Login successful",
            token,
            isVisited,
            email,
            isAdmin: user.isAdmin,
        });
    } catch (error) {
        console.error("🚨 Login error:", error);
        res.status(500).json({ message: "Server error" });
    }
});

//google-signup

app.post("/firebase-signup", async (req, res) => {
    const { name, email, firebaseToken } = req.body;
    if (!firebaseToken)
        return res
            .status(400)
            .json({ message: "Firebase ID token is required." });

    try {
        const decoded = await admin.auth().verifyIdToken(firebaseToken);
        const firebaseUid = decoded.uid;
        const firebaseEmail = decoded.email;
        // Prevent duplicate signup
        const existingByUid = await User.findOne({ firebaseUid });
        if (existingByUid)
            return res.status(400).json({
                message: "User already registered with this Firebase account.",
            });

        const existingByEmail = await User.findOne({ email: firebaseEmail });
        if (existingByEmail)
            return res.status(400).json({
                message:
                    "Email already in use. Please log in or use a different email.",
            });

        const user = await new User({
            email: firebaseEmail,
            firebaseUid,
        }).save();

        res.status(201).json({
            message: "Firebase signup successful",
            user,
        });
    } catch (err) {
        console.error("Firebase Signup error:", err);
        res.status(500).json({ message: "Signup failed", error: err.message });
    }
});

//google-login

app.post("/firebase-login", async (req, res) => {
    const { token: firebaseIdToken } = req.body;
    if (!firebaseIdToken)
        return res
            .status(400)
            .json({ message: "Firebase ID token is required" });

    try {
        const decoded = await admin.auth().verifyIdToken(firebaseIdToken);
        const { uid: firebaseUid, email } = decoded;

        let user = await User.findOne({ firebaseUid });

        if (!user) {
            // Try linking if same email exists
            user = await User.findOne({ email });
            if (user) {
                user.firebaseUid = firebaseUid;
                await user.save();
            } else {
                user = await new User({
                    email,
                    firebaseUid,
                }).save();
            }
        }
        const isVisited = user.isVisited;
        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET
        );

        res.json({
            message: "Firebase login successful",
            token,
            user,
            isVisited,
        });
    } catch (err) {
        console.error("Firebase Login error:", err);
        res.status(500).json({
            message: "Firebase login failed",
            error: err.message,
        });
    }
});

//reset-password

app.post("/reset-password/:token", async (req, res) => {
    const newPassword = req.body.password;
    if (!newPassword) {
        return res.status(400).json({ message: "New password is required." });
    }

    try {
        const hashedToken = crypto
            .createHash("sha256")
            .update(req.params.token)
            .digest("hex");

        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() },
        }).select("+password");

        if (!user) {
            return res
                .status(400)
                .json({ message: "Token is invalid or expired." });
        }

        user.password = newPassword;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();

        res.status(200).json({ message: "Password has been reset." });
    } catch (err) {
        console.error("Reset password error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

//user details

app.post("/personal-info", auth, async (req, res) => {
    const userId = req.user.id;

    const { name, gender, phone, dob, profession } = req.body;

    try {
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            {
                ...(name && { name }),
                ...(gender && { gender }),
                ...(phone && { phone }),
                ...(dob && { dob }),
                ...(profession && { profession }),
                isVisited: true,
            },
            {
                new: true,
                runValidators: true,
                select: "-password", // Exclude password from response
            }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({
            message: "Profile updated successfully",
            user: updatedUser,
        });
    } catch (err) {
        console.error("Profile Update Error:", err);
        res.status(500).json({
            message: "Server error while updating profile",
        });
    }
});

app.get("/aboutme", auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .select("name email profession") // Fetch only necessary user fields
            .populate({
                path: "posts",
                select: "type title content likes comments genres createdAt", // ✅ Include genres
                options: { sort: { createdAt: -1 } }, // Sort posts by newest first
            })
            .lean(); // Return plain JS object for performance

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // DEBUG: Check the structure of user.posts
        console.log("User Posts:", user.posts);

        // Extract unique genres from user's posts
        const genresTouched = [
            ...new Set(user.posts.flatMap((post) => post.genres || [])),
        ];

        // Prepare posts for frontend
        const processedPosts = user.posts.map((post) => ({
            id: post._id, // Map _id to id for frontend consistency
            title: post.title,
            content: post.content,
            type: post.type,
            likeCount: post.likes?.length || 0,
            commentCount: post.comments?.length || 0,
        }));

        // Final response object
        const responseData = {
            name: user.name,
            email: user.email,
            profession: user.profession,
            posts: processedPosts,
            genresTouched: genresTouched,
        };

        res.json(responseData);
    } catch (err) {
        console.error("Error in /aboutme:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// --- /aboutme/update route (Unchanged) ---
app.post("/aboutme/update", auth, async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, email, profession } = req.body; // Removed genresTouched as it's derived
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $set: { name, email, profession } },
            { new: true }
        ).select("name email profession");

        if (!updatedUser) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json({
            message: "Profile updated successfully",
            user: updatedUser,
        });
    } catch (err) {
        console.error("Profile update error:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// --- NEW: Route to delete a post ---
app.delete("/posts/:id", auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const postId = req.params.id;
        const userId = req.user._id;

        // 1. Find the post and verify ownership
        const post = await Post.findById(postId).session(session);
        if (!post) {
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json({ message: "Post not found" });
        }

        // Security check: only the author can delete their post
        if (!post.author.equals(userId)) {
            await session.abortTransaction();
            session.endSession();
            return res
                .status(403)
                .json({
                    message:
                        "Authorization denied. You can only delete your own posts.",
                });
        }

        // 2. Delete all comments associated with the post
        await Comment.deleteMany({ post: postId }).session(session);

        // 3. Remove the post reference from the author's document
        await User.updateOne(
            { _id: userId },
            { $pull: { posts: postId } }
        ).session(session);

        // 4. Delete the post itself
        await Post.findByIdAndDelete(postId).session(session);

        // If all operations succeed, commit the transaction
        await session.commitTransaction();
        session.endSession();

        res.json({
            message: "Post and associated comments deleted successfully.",
        });
    } catch (err) {
        // If any operation fails, abort the transaction
        await session.abortTransaction();
        session.endSession();
        console.error("Error deleting post:", err);
        res.status(500).json({ message: "Server error during post deletion." });
    }
});

//posts

app.post("/create-post", auth, async (req, res) => {
    try {
        const userId = req.user.id;

        const { title, content, description, language, genres, type } =
            req.body;

        // Validate required fields
        if (
            !title ||
            !content ||
            !description ||
            !language ||
            !genres ||
            !type
        ) {
            return res.status(400).json({ error: "All fields are required" });
        }

        // Create post
        const newPost = new Post({
            title,
            content,
            description,
            language,
            genres,
            type,
            author: userId,
        });

        const savedPost = await newPost.save();

        // Push the post to the user's "posts" array if you maintain reverse reference
        await User.findByIdAndUpdate(
            userId,
            {
                $addToSet: {
                    genresTouched: { $each: genres }, // Ensures no duplicates
                    posts: savedPost._id,
                },
            },
            { new: true }
        );

        res.status(201).json({
            message: "Post created successfully",
            post: savedPost,
        });
    } catch (error) {
        console.error("Error creating post:", error);
        res.status(500).json({ error: "Server error" });
    }
});

//poems-telugu
app.get("/telugu-poems", async (req, res) => {
    try {
        const poems = await Post.find(
            { language: "te", type: "poem" },
            { title: 1, content: 1, _id: 0 } // project title and content only
        )
            .sort({ createdAt: -1 }) // sort by most recent
            .limit(5); // return only latest 5 poems

        res.json(poems);
    } catch (err) {
        console.error("Error fetching Telugu poems:", err);
        res.status(500).json({ error: "Failed to fetch recent Telugu poems" });
    }
});
// ENGLISH POEMS
app.get("/english-poems", async (req, res) => {
    try {
        const poems = await Post.find(
            { language: "en", type: "poem" },
            { title: 1, content: 1, _id: 0 }
        )
            .sort({ createdAt: -1 })
            .limit(5);

        res.json(poems);
    } catch (err) {
        console.error("Error fetching English poems:", err);
        res.status(500).json({
            error: "Failed to fetch English poems content",
        });
    }
});

// TELUGU STORIES
app.get("/telugu-stories", async (req, res) => {
    try {
        const stories = await Post.find(
            { language: "te", type: "story" },
            { title: 1, content: 1, _id: 0 }
        )
            .sort({ createdAt: -1 })
            .limit(5);

        res.json(stories);
    } catch (err) {
        console.error("Error fetching Telugu stories:", err);
        res.status(500).json({
            error: "Failed to fetch Telugu stories content",
        });
    }
});

// ENGLISH STORIES
app.get("/english-stories", async (req, res) => {
    try {
        const stories = await Post.find(
            { language: "en", type: "story" },
            { title: 1, content: 1, _id: 0 }
        )
            .sort({ createdAt: -1 })
            .limit(5);

        res.json(stories);
    } catch (err) {
        console.error("Error fetching English stories:", err);
        res.status(500).json({
            error: "Failed to fetch English stories content",
        });
    }
});

// TELUGU ESSAYS
app.get("/telugu-essays", async (req, res) => {
    try {
        const essays = await Post.find(
            { language: "te", type: "essay" },
            { title: 1, content: 1, _id: 0 }
        )
            .sort({ createdAt: -1 })
            .limit(5);

        res.json(essays);
    } catch (err) {
        console.error("Error fetching Telugu essays:", err);
        res.status(500).json({
            error: "Failed to fetch Telugu essays content",
        });
    }
});

// ENGLISH ESSAYS
app.get("/english-essays", async (req, res) => {
    try {
        const essays = await Post.find(
            { language: "en", type: "essay" },
            { title: 1, content: 1, _id: 0 }
        )
            .sort({ createdAt: -1 })
            .limit(5);

        res.json(essays);
    } catch (err) {
        console.error("Error fetching English essays:", err);
        res.status(500).json({
            error: "Failed to fetch English essays content",
        });
    }
});

// 1. Telugu Poems All
app.get("/telugu-poems-all", async (req, res) => {
    try {
        const poems = await Post.find({ language: "te", type: "poem" })
            .sort({ createdAt: -1 })
            .populate("author", "name") // author name only
            .populate({
                path: "comments",
                populate: {
                    path: "user",
                    select: "name",
                },
            });

        const formatted = poems.map((p) => ({
            id: p._id,
            title: p.title,
            content: p.content,
            author: p.author?.name || "Unknown",
            genre: p.genres?.[0] || "General", // only first genre
            date: p.createdAt,
            likes: p.likes?.length || 0,
            isLiked: false, // default unless you check user from req
            comments: (p.comments || []).map((c) => ({
                id: c._id,
                user: c.user?.name || "Anonymous",
                content: c.content,
                date: c.createdAt,
            })),
        }));

        res.json(formatted);
    } catch (err) {
        console.error("Error fetching Telugu poems:", err);
        res.status(500).json({ error: "Failed to fetch Telugu poems" });
    }
});

// 2. English Poems All
app.get("/english-poems-all", async (req, res) => {
    try {
        const poems = await Post.find(
            { language: "en", type: "poem" },
            { title: 1, content: 1, _id: 0 }
        ).sort({ createdAt: -1 });

        res.json(poems);
    } catch (err) {
        console.error("Error fetching English poems:", err);
        res.status(500).json({ error: "Failed to fetch English poems" });
    }
});

// 3. Telugu Stories All
app.get("/telugu-stories-all", async (req, res) => {
    try {
        const stories = await Post.find(
            { language: "te", type: "story" },
            { title: 1, content: 1, _id: 0 }
        ).sort({ createdAt: -1 });

        res.json(stories);
    } catch (err) {
        console.error("Error fetching Telugu stories:", err);
        res.status(500).json({ error: "Failed to fetch Telugu stories" });
    }
});

// 4. English Stories All
app.get("/english-stories-all", async (req, res) => {
    try {
        const stories = await Post.find(
            { language: "en", type: "story" },
            { title: 1, content: 1, _id: 0 }
        ).sort({ createdAt: -1 });

        res.json(stories);
    } catch (err) {
        console.error("Error fetching English stories:", err);
        res.status(500).json({ error: "Failed to fetch English stories" });
    }
});

// 5. Telugu Essays All
app.get("/telugu-essays-all", async (req, res) => {
    try {
        const essays = await Post.find(
            { language: "te", type: "essay" },
            { title: 1, content: 1, _id: 0 }
        ).sort({ createdAt: -1 });

        res.json(essays);
    } catch (err) {
        console.error("Error fetching Telugu essays:", err);
        res.status(500).json({ error: "Failed to fetch Telugu essays" });
    }
});

// 6. English Essays All
app.get("/english-essays-all", async (req, res) => {
    try {
        const essays = await Post.find(
            { language: "en", type: "essay" },
            { title: 1, content: 1, _id: 0 }
        ).sort({ createdAt: -1 });

        res.json(essays);
    } catch (err) {
        console.error("Error fetching English essays:", err);
        res.status(500).json({ error: "Failed to fetch English essays" });
    }
});

app.get("/posts", auth, async (req, res) => {
    try {
        const { type, language } = req.query;
        const filter = {};
        if (type) filter.type = type;
        if (language) filter.language = language;

        const posts = await Post.find(filter)
            .select(
                "title description content type language likes comments createdAt genres author"
            ) // select only needed fields
            .populate("author", "name")
            .sort({ createdAt: -1 })
            .lean(); // Use .lean() for faster, plain JS objects

        // Add `isLiked` field for the current user
        const postsWithLikeStatus = posts.map((post) => ({
            ...post,
            isLiked: post.likes.some((likeId) => likeId.equals(req.user._id)),
        }));

        res.json(postsWithLikeStatus);
    } catch (err) {
        console.error("Error fetching posts:", err);
        res.status(500).json({ error: "Failed to fetch posts" });
    }
});

// Get a single post with fully populated comments
app.get("/posts/:id", auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id)
            .populate({
                path: "comments",
                populate: { path: "user", select: "name" },
            })
            .populate("author", "name")
            .lean();
        if (!post) {
            return res.status(404).json({ error: "Post not found" });
        }
        res.json(post);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Like/Unlike a post
app.post("/posts/:id/like", auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ error: "Post not found" });

        const userId = req.user._id;
        const isLiked = post.likes.includes(userId);

        if (isLiked) {
            post.likes = post.likes.filter((id) => !id.equals(userId));
        } else {
            post.likes.push(userId);
        }

        await post.save();
        // Return the new state so the frontend doesn't have to guess
        res.json({ likes: post.likes.length, isLiked: !isLiked });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add a comment to a post
app.post("/posts/:id/comments", auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ error: "Post not found" });

        const comment = new Comment({
            content: req.body.content,
            post: req.params.id,
            user: req.user._id,
        });

        await comment.save();

        // Populate the user field of the new comment before sending back
        await comment.populate("user", "name");

        post.comments.push(comment._id);
        await post.save();

        res.status(201).json(comment); // Return the newly created comment object
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

//uptime
app.get("/uptimerobot", async (req, res) => {
    console.log("UptimeRobot ping received");
    res.status(200).send("OK"); // Important: always respond
});

//youtube - upload

app.post('/youtube-uploads', auth, async (req, res) => {
  try {
    const {
      title,
      content,
      description,
      category,
      language
    } = req.body;

    const authorId = req.user; // 👈 Comes from auth middleware

    if (!mongoose.Types.ObjectId.isValid(authorId)) {
      return res.status(400).json({ error: 'Invalid author ID from token.' });
    }

    const newUpload = new YouTubeUpload({
      title,
      author: authorId,
      content,
      description,
      category,
      language,
    });

    const savedUpload = await newUpload.save();
    res.status(201).json(savedUpload);
  } catch (err) {
    console.error('Upload Error:', err);
    res.status(500).json({ error: 'Server Error' });
  }
});

//  GET all YouTube uploads 
app.get('/youtube-uploads', async (req, res) => {
  try {
    const uploads = await YouTubeUpload.find()
      .populate('author', 'name email') // populate author's name and email (optional)
      .sort({ submissionDate: -1 });    // sort newest first

    res.status(200).json(uploads);
  } catch (err) {
    console.error('Error fetching uploads:', err);
    res.status(500).json({ error: 'Server Error' });
  }

});

app.post("/competitions-upload", auth, async (req, res) => {
  try {
    const {
      name,
      phone,
      college,
      email,
      roll,
      content,
      description,
    } = req.body;

    const authorId = req.user; // assuming this is user._id from auth middleware

    // 🔍 Check if user already submitted
    const existingSubmission = await CompetitionSubmission.findOne({
      author: authorId,
      isSubmitted: true
    });

    if (existingSubmission) {
      return res.status(400).json({ error: "మీరు ఇప్పటికే సమర్పించారు." });
    }

    // ✅ Create and mark as submitted
    const newSubmission = new CompetitionSubmission({
      name,
      phone,
      college,
      email,
      roll,
      content,
      description,
      author: authorId,        // ✅ Save author ID
      isSubmitted: true
    });

    await newSubmission.save();

    res.status(201).json({
      message: "Submitted successfully!",
      data: newSubmission
    });

  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: "ఈ రోల్ నంబర్ నుండి ఇప్పటికే సమర్పించబడింది." });
    }
    res.status(500).json({ error: "Server error." });
  }
});



// GET /api/competition-upload (Return all/filtered submissions)
app.get("/competitions-fetch", async (req, res) => {
  try {
    // Optionally filter, paginate, or search here
    const submissions = await CompetitionSubmission.find({ submission_type: "competition" })
      .sort({ createdAt: -1 });
    res.json(submissions);
  } catch (err) {
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/admin/stats", auth, async (req, res) => {
  try {
    const users_count = await User.countDocuments();
    const poems_count = await Post.countDocuments({ type: "poem" });
    const stories_count = await Post.countDocuments({ type: "story" });
    const essays_count = await Post.countDocuments({ type: "essay" });
    const VideoGallery_count = await YouTubeUpload.countDocuments();
    res.json({ users_count, poems_count, stories_count, essays_count ,VideoGallery_count});
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// GET all users with post count
app.get("/admin/users", auth, async (req, res) => {
  try {
    const users = await User.find()
      .populate("posts", "_id") // Only populate _id for count
      .select("-password"); // Exclude password

    const usersWithPostCount = users.map((user) => ({
      ...user.toObject(),
      postCount: user.posts.length,
    }));

    res.json({ data: usersWithPostCount });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});
// DELETE a user by ID
app.delete("/admin/users/:id", auth, async (req, res) => {
  try {
    const { id } = req.params;

    // Optional: Delete related posts if required
    // await Post.deleteMany({ user: id });

    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) return res.status(404).json({ error: "User not found" });

    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

app.get("/admin/competition-submissions", auth, async (req, res) => {
  try {
    const submissions = await CompetitionSubmission.find()
      .populate("author", "name email") // populate only name and email from User model
      .sort({ createdAt: -1 });

    res.json({ data: submissions });
  } catch (err) {
    console.error("Failed to fetch submissions:", err);
    res.status(500).json({ error: "Failed to fetch submissions" });
  }
});

app.get("/admin/poems", async (req, res) => {
  const { language } = req.query;
  const filter = { type: "poem" };
  if (language) filter.language = language;

  try {
    const poems = await Post.find(filter)
      .populate("author", "name") // fetches author's name only
      .sort({ createdAt: -1 });

    res.json({ success: true, data: poems });
  } catch (err) {
    console.error("Error fetching poems:", err);
    res.status(500).json({ success: false, error: "Failed to fetch poems" });
  }
});

app.delete("/admin/poems/:id", auth, async (req, res) => {
  const { id } = req.params;

  try {
    const deletedPoem = await Post.findByIdAndDelete(id);
    if (!deletedPoem) {
      return res.status(404).json({ success: false, message: "Poem not found" });
    }

    res.status(200).json({ success: true, message: "Poem deleted successfully" });
  } catch (err) {
    console.error("Error deleting poem:", err);
    res.status(500).json({ success: false, message: "Failed to delete poem" });
  }
});

app.get("/admin/stories", async (req, res) => {
  const { language } = req.query;
  const filter = { type: "story" };
  if (language) filter.language = language;

  try {
    const stories = await Post.find(filter)
      .populate("author", "name") // fetches author's name only
      .sort({ createdAt: -1 });

    res.json({ success: true, data: stories });
  } catch (err) {
    console.error("Error fetching stories:", err);
    res.status(500).json({ success: false, error: "Failed to fetch stories" });
  }
});

app.delete("/admin/stories/:id", auth, async (req, res) => {
  const { id } = req.params;

  try {
    const deletedStory = await Post.findByIdAndDelete(id);
    if (!deletedStory) {
      return res.status(404).json({ success: false, message: "Story not found" });
    }

    res.status(200).json({ success: true, message: "Stroy deleted successfully" });
  } catch (err) {
    console.error("Error deleting story:", err);
    res.status(500).json({ success: false, message: "Failed to delete story" });
  }
});

app.get("/admin/essays", async (req, res) => {
  const { language } = req.query;
  const filter = { type: "essay" };
  if (language) filter.language = language;

  try {
    const essays = await Post.find(filter)
      .populate("author", "name") // fetches author's name only
      .sort({ createdAt: -1 });

    res.json({ success: true, data: essays });
  } catch (err) {
    console.error("Error fetching essays:", err);
    res.status(500).json({ success: false, error: "Failed to fetch essays" });
  }
});

app.delete("/admin/essays/:id", auth, async (req, res) => {
  const { id } = req.params;

  try {
    const deletedEssay = await Post.findByIdAndDelete(id);
    if (!deletedEssay) {
      return res.status(404).json({ success: false, message: "Essay not found" });
    }

    res.status(200).json({ success: true, message: "Essay deleted successfully" });
  } catch (err) {
    console.error("Error deleting Essay:", err);
    res.status(500).json({ success: false, message: "Failed to delete Essay" });
  }
});

app.get("/admin/competition", async (req, res) => {
  const { language } = req.query;
  const filter = {}; // You can use language filter later if needed

  try {
    const competitions = await Competition.find(filter)
      .populate("author", "name email phoneNumber rollNumber") // ⬅️ all required fields
      .sort({ createdAt: -1 });

    res.json({ success: true, data: competitions });
  } catch (err) {
    console.error("Error fetching competitions:", err);
    res.status(500).json({ success: false, error: "Failed to fetch competitions" });
  }
});


app.delete("/admin/competition/:id", auth, async (req, res) => {
  const { id } = req.params;

  try {
    const deleted = await Competition.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).json({ success: false, message: "Submission not found" });
    }

    res.status(200).json({ success: true, message: "Submission deleted successfully" });
  } catch (err) {
    console.error("Error deleting submission:", err);
    res.status(500).json({ success: false, message: "Failed to delete submission" });
  }
});

app.get("/admin/videogallery", auth, async (req, res) => {
  try {
    const videos = await YouTubeUpload.find({
      content: { $regex: /^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.?be)\// },
      isVerified: false  // ✅ Only unverified videos
    })
      .populate("author", "name")
      .sort({ submissionDate: -1 });

    res.status(200).json({ success: true, data: videos });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to fetch video gallery" });
  }
});

app.get("/admin/videogallery/all", auth, async (req, res) => {
  try {
    const videos = await YouTubeUpload.find({
      content: { $regex: /^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.?be)\// },
      
    })
      .populate("author", "name")
      .sort({ submissionDate: -1 });

    res.status(200).json({ success: true, data: videos });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to fetch video gallery" });
  }
});


// 🗑️ DELETE: Delete a video submission by ID
app.delete("/admin/videogallery/:id", auth, async (req, res) => {
  try {
    const deleted = await YouTubeUpload.findByIdAndDelete(req.params.id);
    if (!deleted) {
      return res.status(404).json({ success: false, error: "Video not found" });
    }
    res.status(200).json({ success: true, message: "Video deleted successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to delete video" });
  }
});

// ✅ POST: Mark a video as accepted (isVerified = true)
app.post("/admin/videogallery/:id/accept", auth ,async (req, res) => {
  try {
    const video = await YouTubeUpload.findByIdAndUpdate(
      req.params.id,
      { isVerified: true },
      { new: true }
    );
    if (!video) {
      return res.status(404).json({ success: false, error: "Video not found" });
    }
    res.status(200).json({ success: true, message: "Video accepted", data: video });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to accept video" });
  }
});

//chatbot
const GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
app.post("/chat", async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ text: "Prompt required" });

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
    });

    // Response will have a `text` field.
    res.json({ text: response.text || "No response." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ text: "Error contacting Gemini API." });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
