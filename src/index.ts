
console.log("Welcome to Pandaura Backend");

import express from 'express';

import { initializeTables } from './db/tables';


const app = express();
const port = 5000;
initializeTables();

app.get('/', (req, res) => {
  res.send('Pandaura backend is running...');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});