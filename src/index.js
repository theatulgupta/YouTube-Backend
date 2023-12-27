import dotenv from 'dotenv';
import connectDB from "./db/index.js";
import { app } from './app.js';

// Load environment variables from the specified file
dotenv.config({ path: './.env' });

// Connect to the MongoDB database
connectDB()
    .then(() => {
        // Handle errors in the application
        app.on("error", (err) => {
            console.log("ERROR: ", err);
        });

        // Start the Express server on the specified port or default to 8000
        const port = process.env.PORT || 8000;
        app.listen(port, () => {
            console.log(`Server is running at port: ${port}`);
        });
    })
    .catch((error) => {
        console.log("MONGODB connection failed !!!", error);
    });