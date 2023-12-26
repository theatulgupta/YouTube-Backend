import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from 'jsonwebtoken';

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        // Retrieve user from the database and select only necessary fields
        const user = await User.findById(userId).select('refreshToken');

        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        // Generate new access and refresh tokens
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        // Update refreshToken in the database
        await User.findByIdAndUpdate(userId, { $set: { refreshToken } }, { new: true, runValidators: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, 'Error generating refresh & access tokens');
    }
};

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        // Retrieve refresh token from cookies or request body
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

        // Check if refresh token is missing
        if (!incomingRefreshToken) {
            throw new ApiError(401, "Unauthorized request");
        }

        // Verify the incoming refresh token
        const decodedRefreshToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );

        // Find the user associated with the refresh token
        const user = await User.findById(decodedRefreshToken?._id);

        // Check if user is not found
        if (!user) {
            throw new ApiError(401, "Invalid refresh token");
        }

        // Check if incoming refresh token matches the stored refresh token
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used");
        }

        // Generate new access and refresh tokens
        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id);

        // Set cookie options
        const options = {
            httpOnly: true,
            secure: true,
        };

        // Set new cookies in the response
        res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            );
    } catch (error) {
        // Handle token verification or user retrieval errors
        throw new ApiError(401, error?.message || "Invalid refresh token");
    }
});

const registerUser = asyncHandler(async (req, res) => {

    // get user details from frontend
    const { fullname, email, username, password } = req.body;
    // console.log(req.body);

    // validation - not empty
    if ([fullname, email, username, password].some(
        (field) => field?.trim() === ""
    )) { throw new ApiError(400, "All fields are required") };

    // check if user already exists: username, email
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists");
    }

    // console.log(req.files);

    // check for images, check for avatar
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    // check for avatar
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required");
    }

    // upload them to cloudinary, avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required");
    }

    // create user object - create entry in db
    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    });

    // remove password and refresh token field from response
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    // check for user creation
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user");
    }

    // return response
    return res.status(202).json(new ApiResponse(200, createdUser, "User registered successfully"))
});

const loginUser = asyncHandler(async (req, res) => {
    // req body -> data
    const { email, username, password } = req.body;

    // username or email is required
    if (!(username || email)) {
        throw new ApiError(400, "username or email is required");
    }

    // find user based on username or email
    const user = await User.findOne({
        $or: [{ username }, { email }]
    });

    // user doesn't exist
    if (!user) {
        throw new ApiError(404, "user doesn't exist");
    }

    // password check
    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials");
    }

    // access and refresh token based on userId
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

    // fetching updated user - optional
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    // send cookies (secure)
    const options = {
        httpOnly: true,
        secure: true
    };

    // Ensure loggedInUser is converted to a plain JavaScript object before sending it in the response
    const plainLoggedInUser = loggedInUser.toObject();

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(new ApiResponse(
            200,
            {
                user: plainLoggedInUser, accessToken, refreshToken
            },
            "User logged In successfully"
        ));
});

const logoutUser = asyncHandler(async (req, res) => {
    // Update refreshToken to undefined in the database
    const updatedUser = await User.findByIdAndUpdate(
        req.user._id,
        { $set: { refreshToken: undefined } }, // Set refreshToken to undefined
        { new: true } // Return the updated user document
    );

    // Clear cookies in the response
    const options = {
        httpOnly: true, // Set HttpOnly flag for security
        secure: true,   // Set secure flag for HTTPS-only cookies
    };

    return res
        .status(200)
        .clearCookie("accessToken", options)    // Clear accessToken cookie
        .clearCookie("refreshToken", options)   // Clear refreshToken cookie
        .json(new ApiResponse(200, {}, "User logged out"));
});

export { registerUser, loginUser, logoutUser, refreshAccessToken };