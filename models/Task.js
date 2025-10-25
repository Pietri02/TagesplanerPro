const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: String,
  category: String,
  priority: {
    type: String,
    enum: ['low', 'normal', 'high'],
    default: 'normal'
  },
  status: {
    type: String,
    enum: ['open', 'waiting', 'completed', 'archived'],
    default: 'open'
  },
  dueDate: String,
  startDate: String,
  recurrence: String,
  duration: Number,
  tags: [String],
  sharedWith: [String],
  comments: String,
  owner: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  completedAt: Date,
  history: [{
    action: String,
    timestamp: Date,
    user: String,
    changes: Object
  }]
});

module.exports = mongoose.model('Task', taskSchema);
