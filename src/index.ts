
console.log("Welcome to Pandaura Backend");

import express from 'express';

const app = express();
const port = 5000;

app.get('/', (req, res) => {
  res.send('Pandaura backend is running...');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});