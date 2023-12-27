import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const app = express();

// Enable Cross-Origin Resource Sharing (CORS) with specified origin and credentials
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}));

// Major Configurations -> Production Level Code

// Parse incoming JSON requests with a size limit of 16kb
app.use(express.json({ limit: "16kb" }));

// Parse URL-encoded data with extended support and a size limit of 16kb
app.use(express.urlencoded({ extended: true, limit: "16kb" }));

// Serve static files from the "public" directory
app.use(express.static("public"));

// Parse cookies using cookie-parser middleware
app.use(cookieParser());

// Routes import
import userRouter from './routes/user.routes.js';

// Routes declaration
app.use("/api/v1/users", userRouter);

export { app };
