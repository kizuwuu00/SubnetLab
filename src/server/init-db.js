import 'dotenv/config';
import { db } from './db.js';
db.close();
console.log('SubnetLab database initialized.');
