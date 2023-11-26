import axios from 'axios';

export const getProducts = async (req, res) => {
  await axios.get('https://dummyjson.com/products?limit=100')
    .then((axios_res) => res.json({ response: axios_res.data.products, success: true }))
    .catch((error) => res.json({ response: error.message, success: false }));
}

export const getProductById = async (req, res) => {
  await axios.get('https://dummyjson.com/products/' + req.params.productId)
    .then((axios_res) => res.json({ response: axios_res.data, success: true }))
    .catch((error) => res.json({ response: error.message, success: false }));
}