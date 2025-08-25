const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: false,
  },
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    select: false,
  },
  dob: Date,
  isVisited: {
    type: Boolean,
    default: false,
  },
  genresTouched: [String],
  phoneNumber: {
    type: String,
    validate: {
      validator: v => /^\+?[0-9]{10,14}$/.test(v),
      message: props => `${props.value} is not a valid phone number!`
    }
  },
  posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
  profession: String,
  gender: {
    type: String,
    enum: ["Male", "Female", "Other"],
  },
  isLiked: {
    type: Boolean,
    default: false,
  },
  firebaseUid: {
    type: String,
    unique: true,
    sparse: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  passwordResetToken: String,
  passwordResetExpires: Date,
  isAdmin:{
    type:Boolean,
    default:false,
  },
  // ✅ Renamed from "submissions"
  youtubeUploads: [{ type: mongoose.Schema.Types.ObjectId, ref: 'YouTubeUpload' }],
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return resetToken;
};

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

module.exports = mongoose.model('User', userSchema);
