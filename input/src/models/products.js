import { Schema, model } from 'mongoose';

const productSchema = new Schema({
  name: String,
  category: String,
  price: Number,
  imageUrl: String,
  rate: Number,
}, {
  timestamp: true,
  versionKey: false
});

export default model('Product', productSchema);