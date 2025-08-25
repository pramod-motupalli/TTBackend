const mongoose = require('mongoose');

const youtubeUploadSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'A title is required.'],
    trim: true,
  },

  // ✅ Replaced with reference to User
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },

  content: {
    type: String,
    required: [true, 'Content (text or a YouTube link) is required.'],
  },

  description: {
    type: String,
    trim: true,
    default: '',
  },

  category: {
    type: String,
    required: true,
    enum: ['poem', 'story', 'essay'],
  },

  language: {
    type: String,
    required: true,
    enum: ['te', 'en'],
  },

  isVerified: {
    type: Boolean,
    default: false,
  },

  submissionDate: {
    type: Date,
    default: Date.now,
  },

  
});

// Automatically detect YouTube video
youtubeUploadSchema.pre('save', function (next) {
  const YOUTUBE_URL_REGEX = /^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.?be)\/.+$/;
  this.isYouTubeVideo = YOUTUBE_URL_REGEX.test(this.content);
  next();
});

// Indexing for optimized queries
youtubeUploadSchema.index({ language: 1, category: 1, isApproved: 1 });

module.exports = mongoose.model('YouTubeUpload', youtubeUploadSchema);
