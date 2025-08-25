const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');

exports.forgotPassword = async (req, res) => {
    let user;

    try {
      
        // 1) Get user (no select — get entire object)
        user = await User.findOne({ email: req.body.email });
        if (!user) {
                       return res.status(404).json({ message: 'Email not found or a technical error occurred.' });
        }

        // Log full user object
       
        // 2) Check for Google Sign-In based on firebaseUid
        const isGoogleUser = user.firebaseUid && !user.password;
        
        if (isGoogleUser) {
               return res.status(400).json({
                message: 'This account is registered via Google Sign-In. Password reset is not available.',
                type: 'google-login'
            });
        }

    
        // 3) Generate the random reset token
        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false });

        const resetURL = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

        const message = `
            <h2>Password Reset Request for TeluguTilakam</h2>
            <p>You requested a password reset. Please click the link below to set a new password. This link is valid for only 10 minutes.</p>
            <a href="${resetURL}" style="background-color: #f97316; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Your Password</a>
            <p>If you didn't request this, please ignore this email.</p>
        `;

        
        await sendEmail({
            email: user.email,
            subject: 'Your Password Reset Link (Valid for 10 min)',
            html: message,
        });

        
        res.status(200).json({
            status: 'success',
            message: 'A password reset link has been sent to your email.',
        });

    } catch (err) {
        if (user) {
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save({ validateBeforeSave: false });
        }

        console.error('❌ FORGOT PASSWORD ERROR:', err);
        res.status(500).json({ message: 'There was an error sending the email. Please try again later.' });
    }
};
