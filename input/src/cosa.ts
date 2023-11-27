//Este archivo no deberia leerlo

import mongoose from 'mongoose';

mongoose.connect("mongodb://mongo/viio_market_showcase")
  .then(db => console.log('Db is connected'))
  .catch(error => console.log(error));

// mongoose.connect("mongodb://localhost/viio_market_showcase")
//   .then(db => console.log('Db is connected'))
//   .catch(error => console.log(error));