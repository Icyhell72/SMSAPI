const express = require('express');
const bcrypt = require('bcryptjs');
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

const sendSMS = require('./smsService.js'); // Import your SMS service provider
const sendSMSPassword  = require ('./smsPassword')
const router = express.Router();
const MAX_VERIFICATION_ATTEMPTS = 2;
const BLOCK_DURATION = 30 * 60 * 1000; // 30 minutes in milliseconds

// Create a Map to store the verification attempts for each user
const verificationAttempts = new Map();
const MAX_PASSWORD_RESET_ATTEMPTS = 2;

// Create a Map to store the password reset attempts for each user
const passwordResetAttempts = new Map();
// @route    POST api/auth/register
// Registration route
router.post(
  '/register',
  [
    // Validation middleware
    check('phone', 'Phone is required').notEmpty(),
    check(
      'phone',
      'Please enter a valid phone number with exactly 8 numbers'
    ).matches(/^\d{8}$/),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { phone } = req.body;

    try {
      let user = await User.findOne({ phone });

      if (user) {
        return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
      }

      // Generate a random 6-digit verification code (numbers only)
      const verificationCode = String(Math.floor(100000 + Math.random() * 900000)); // Generates a random 6-digit number

      // Send SMS with the verification code
      await sendSMS(phone, verificationCode);

      // Create a new user with phone and verification code
      user = new User({
        phone,
        codeVerification: verificationCode,
      });

      await user.save();

      // Use a timer to remove the `codeVerification` field after 2 minutes
      setTimeout(async () => {
        await User.updateOne({ _id: user._id }, { $unset: { codeVerification: 1 } });
      }, 2 * 60 * 1000); // 2 minutes in milliseconds

      res.json({ msg: 'Verification code sent successfully' });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);
// @route    POST api/auth/resend-verification-code/phone
// resend verification code route

router.post('/resend-verification-code/:phone', async (req, res) => {
  const { phone } = req.params; // Get the phone number from the URL

  let userAttempts = verificationAttempts.get(phone) || 0;

  try {
    if (userAttempts >= MAX_VERIFICATION_ATTEMPTS) {
      // Check if the user is temporarily blocked
      const lastAttemptTime = verificationAttempts.get(`${phone}_lastAttempt`);
      if (lastAttemptTime && Date.now() - lastAttemptTime < BLOCK_DURATION) {
        return res.status(429).json({ msg: 'Too many verification attempts. Please try again later.' });
      }
    }

    // Find the user by phone number
    const user = await User.findOne({ phone });

    // Generate a new random 6-digit verification code
    const newVerificationCode = String(Math.floor(100000 + Math.random() * 900000));

    // Update the user's verification code with the new code
    user.codeVerification = newVerificationCode;

    // Save the updated user document
    await user.save();

    // Set a timer to remove the `codeVerification` field after 2 minutes
    setTimeout(async () => {
      await User.updateOne({ _id: user._id }, { $unset: { codeVerification: 1 } });
    }, 2 * 60 * 1000); // 2 minutes in milliseconds

    // Send the new verification code via SMS
    await sendSMS(phone, newVerificationCode);

    // Reset the user's verification attempts
    verificationAttempts.set(phone, 0);

    res.json({ msg: 'New verification code sent successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  } finally {
    // Update the user's verification attempts
    verificationAttempts.set(phone, userAttempts + 1);
    verificationAttempts.set(`${phone}_lastAttempt`, Date.now());
  }
});

// @route    POST api/auth/verify/phone
// @access   Private
// Verification route
router.post('/verify/:phone', [
  // Middleware de validation
  check('verificationCode', 'Le code de vérification est requis').notEmpty(),
  check('verificationCode', 'Le code de vérification doit contenir 6 chiffres').matches(/^\d{6}$/),
], async (req, res) => {
  const { phone } = req.params; // Obtenir le numéro de téléphone depuis l'URL
  const { verificationCode } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Trouver l'utilisateur par le numéro de téléphone
    const user = await User.findOne({ phone });

    if (!user) {
      return res.status(400).json({ errors: [{ msg: 'Utilisateur introuvable' }] });
    }

    // Vérifier si le code de vérification a expiré
    if (!user.codeVerification) {
      return res.status(400).json({ errors: [{ msg: 'Le code de vérification a expiré' }] });
    }

    // Vérifier si le code de vérification fourni correspond au code stocké
    if (user.codeVerification !== verificationCode) {
      return res.status(400).json({ errors: [{ msg: 'Code de vérification invalide' }] });
    }

    // Marquer l'utilisateur comme vérifié
    user.verified = true;
    await user.save();

    // Retourner un message de réussite
    res.json({ msg: 'Vérification réussie' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Erreur serveur');
  }
});

// @route    GET api/auth
// @desc     Get user by token
// @access   Private
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route    POST api/auth
// @desc     Authenticate user & get token
// @access   Public
router.post(
  '/',
  check('phone', 'Phone is required').exists(),
  check('password', 'Password is required').exists(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { phone, password } = req.body;

    try {
      let user = await User.findOne({ phone });

      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials' }] });
      }

      if (!user.verified) {
        return res.status(400).json({ errors: [{ msg: 'User is not verified' }] });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials' }] });
      }

      const payload = {
        user: {
          id: user.id
        }
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: '30d' },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);





// @route   PUT api/auth/password
// @desc    Change a user's password
// @access  Private
router.put('/password', [
  auth,
  check('currentPassword', 'Current password is required').exists(),
  check('password', 'Password must be at least 8 characters').isLength({ min: 8 }),
  check('password', 'Password must contain at least one uppercase letter').matches(/[A-Z]/),
  check('password', 'Password must contain at least one special character').matches(/[$&+,:;=?@#|'<>.^*()%!-]/),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const user = await User.findById(req.user.id);
    const { currentPassword, newPassword } = req.body;

    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res
        .status(400)
        .json({ errors: [{ msg: 'Invalid current password' }] });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.json({ msg: 'Password updated successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});
// @route   PUT api/auth/sendpassword
// @desc    Change a user's password

router.put('/sendpassword', async (req, res) => {
  const { phone } = req.body; // Declare and initialize phone here
  let userAttempts = 0; // Initialize userAttempts to zero

  try {
    // Check if a user with the provided phone number exists
    const user = await User.findOne({ phone });

    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    userAttempts = passwordResetAttempts.get(phone) || 0;

    if (userAttempts >= MAX_PASSWORD_RESET_ATTEMPTS) {
      // Check if the user is temporarily blocked
      const lastAttemptTime = passwordResetAttempts.get(`${phone}_lastAttempt`);
      if (lastAttemptTime && Date.now() - lastAttemptTime < BLOCK_DURATION) {
        return res.status(429).json({ msg: 'Too many password reset attempts. Please try again later.' });
      }
    }
    
    // Generate a new random password with at least 8 characters, one special character, and one uppercase character
    const newPassword = generateRandomPassword();

    // Call sendSMSPassword to send the new password via SMS
    await sendSMSPassword(phone, newPassword);

    // Update the user's password in the database
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    // Reset the user's password reset attempts
    passwordResetAttempts.set(phone, 0);

    res.json({ msg: 'Password reset successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  } finally {
    // Update the user's password reset attempts
    passwordResetAttempts.set(phone, userAttempts + 1);
    passwordResetAttempts.set(`${phone}_lastAttempt`, Date.now());
  }
});

// Function to generate a random password with at least 8 characters, one special character, and one uppercase character
function generateRandomPassword() {
  const specialChars = '!@#$%^&*()_+';
  const uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
  const newPassword = [];

  // Generate at least one special character and one uppercase character
  newPassword.push(specialChars[Math.floor(Math.random() * specialChars.length)]);
  newPassword.push(uppercaseChars[Math.floor(Math.random() * uppercaseChars.length)]);

  // Generate the remaining characters (at least 6) as a combination of uppercase, lowercase, and special characters
  while (newPassword.length < 8) {
    const charSet = uppercaseChars + lowercaseChars + specialChars;
    newPassword.push(charSet[Math.floor(Math.random() * charSet.length)]);
  }

  // Shuffle the password characters to make it random
  for (let i = newPassword.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [newPassword[i], newPassword[j]] = [newPassword[j], newPassword[i]];
  }

  return newPassword.join('');
}
// @route    POST api/auth/continue-registration/phone
// continue-registration route
router.post('/continue-registration/:phone', [
  // Validation middleware
  check('password', 'Password is required').notEmpty(),
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password must be at least 8 characters').isLength({ min: 8 }),
  check('password', 'Password must contain at least one uppercase letter').matches(/[A-Z]/),
  check('password', 'Password must contain at least one special character').matches(/[$&+,:;=?@#|'<>.^*()%!-]/),
  check('firstname', 'Firstname is required').notEmpty(),
  check('lastname', 'Lastname is required').notEmpty(),
  check('gender', 'Gender is required').notEmpty(),
  check('dateofbirth', 'Date of birth is required').notEmpty(),
], async (req, res) => {
  const { phone } = req.params; // Get the phone number from the URL
  const { password, email,firstname, lastname,gender,dateofbirth } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Find the user by phone number
    const user = await User.findOne({ phone });

    if (!user) {
      return res.status(400).json({ errors: [{ msg: 'User not found' }] });
    }

    

    // Hash the password before saving it
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // Set the other fields
    user.email = email;
    user.firstname = firstname;
    user.lastname = lastname;
    user.gender = gender;
    user.dateofbirth = new Date(dateofbirth); // Assuming dateofbirth is a valid date string

    

    // Save the updated user document
    await user.save();

    // Create and send a JWT token for authenticated access
    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(
      payload,
      config.get('jwtSecret'),
      { expiresIn: '30d' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});
module.exports = router;
