require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const session = require('express-session');

const MongoStore =
  require('connect-mongo').default ||
  require('connect-mongo');

const app = express();

const PORT =
  process.env.PORT || 3000;

app.set('trust proxy', 1);

app.use(
  express.json({
    limit: '2mb'
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '2mb'
  })
);

// =====================================================
// CONFIG
// =====================================================

const MONGO_URI =
  process.env.MONGODB_URI ||
  process.env.MONGO_URI;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  'change-this-session-secret';

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME || '';

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || '';

const APP_URL =
  String(
    process.env.APP_URL || ''
  ).replace(/\/$/, '');


// =====================================================
// WATCHPAYS CONFIG
// =====================================================

const WATCHPAYS_MERCHANT_ID =
  process.env.WATCHPAYS_MERCHANT_ID || '';

const WATCHPAYS_API_KEY =
  process.env.WATCHPAYS_API_KEY || '';

const WATCHPAYS_PAYOUT_KEY =
  process.env.WATCHPAYS_PAYOUT_KEY || '';

const WATCHPAYS_PAYIN_URL =
  process.env.WATCHPAYS_PAYIN_URL ||
  'https://api.watchpays.com/v1/create';

const WATCHPAYS_PAYOUT_URL =
  process.env.WATCHPAYS_PAYOUT_URL ||
  'http://api.watchpays.com/payout/payment';

const WATCHPAYS_PAYIN_CALLBACK =
  process.env.WATCHPAYS_PAYIN_CALLBACK ||
  (
    APP_URL
      ? `${APP_URL}/api/watchpays/callback`
      : ''
  );

const WATCHPAYS_PAYOUT_CALLBACK =
  process.env.WATCHPAYS_PAYOUT_CALLBACK ||
  (
    APP_URL
      ? `${APP_URL}/api/watchpays/payout-callback`
      : ''
  );


// =====================================================
// HELPERS
// =====================================================

function moneyToPaise(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return 0;
  }

  return Math.round(number * 100);
}

function paiseToMoney(value) {
  return Number(
    Number(value || 0) / 100
  );
}

function makeRef(prefix = 'REF') {
  return (
    prefix +
    '_' +
    Date.now().toString(36) +
    '_' +
    crypto.randomBytes(5).toString('hex')
  ).toUpperCase();
}

function createSalt() {
  return crypto
    .randomBytes(16)
    .toString('hex');
}

function hashPassword(
  password,
  salt
) {
  return crypto
    .createHash('sha256')
    .update(
      `${salt}:${password}`
    )
    .digest('hex');
}

function verifyPassword(
  password,
  salt,
  passwordHash
) {
  return (
    hashPassword(
      password,
      salt
    ) === passwordHash
  );
}


// =====================================================
// WATCHPAYS PAY-IN SIGNATURE
// =====================================================

function watchPayinSignature({
  merchant_id,
  amount,
  merchant_order_no,
  callback_url
}) {
  const fields = {
    amount,
    callback_url,
    merchant_id,
    merchant_order_no
  };

  const query =
    Object.keys(fields)
      .filter(
        key =>
          fields[key] !== undefined &&
          fields[key] !== null &&
          String(fields[key]) !== ''
      )
      .sort()
      .map(
        key =>
          `${key}=${fields[key]}`
      )
      .join('&');

  return crypto
    .createHash('md5')
    .update(
      `${query}&key=${WATCHPAYS_API_KEY}`
    )
    .digest('hex');
}


// =====================================================
// WATCHPAYS PAYOUT SIGNATURE
// =====================================================

function watchPayoutSignature(data) {
  const raw =
    `${data.account_number}` +
    `${data.amount}` +
    `${data.bank_name}` +
    `${data.callback_url}` +
    `${data.ifsc}` +
    `${data.merchant_id}` +
    `${data.name}` +
    `${data.transaction_id}` +
    `${WATCHPAYS_PAYOUT_KEY}`;

  return crypto
    .createHash('md5')
    .update(raw)
    .digest('hex');
}


// =====================================================
// USER SCHEMA
// =====================================================

const UserSchema =
  new mongoose.Schema(
    {
      name: {
        type: String,
        default: ''
      },

      phone: {
        type: String,
        unique: true,
        required: true,
        index: true
      },

      salt: {
        type: String,
        required: true
      },

      password_hash: {
        type: String,
        required: true
      },

      referral_code: {
        type: String,
        unique: true,
        required: true,
        index: true
      },

      referred_by: {
        type: String,
        default: null
      },

      banned: {
        type: Boolean,
        default: false
      },

      vip_level: {
        type: Number,
        default: 0
      },

      created_at: {
        type: Date,
        default: Date.now
      }
    },
    {
      collection: 'users'
    }
  );

const User =
  mongoose.model(
    'User',
    UserSchema
  );


// =====================================================
// WALLET
// =====================================================

const WalletSchema =
  new mongoose.Schema(
    {
      user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        unique: true,
        required: true,
        index: true
      },

      balance: {
        type: Number,
        default: 0
      },

      updated_at: {
        type: Date,
        default: Date.now
      }
    },
    {
      collection: 'wallets'
    }
  );

const Wallet =
  mongoose.model(
    'Wallet',
    WalletSchema
  );


// =====================================================
// WALLET TRANSACTION
// =====================================================

const WalletTransactionSchema =
  new mongoose.Schema(
    {
      user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
      },

      type: {
        type: String,
        enum: [
          'credit',
          'debit',
          'refund'
        ],
        required: true
      },

      amount: {
        type: Number,
        required: true
      },

      balance_after: {
        type: Number,
        required: true
      },

      reference_type: {
        type: String,
        default: ''
      },

      reference_id: {
        type: String,
        default: ''
      },

      created_at: {
        type: Date,
        default: Date.now
      }
    },
    {
      collection:
        'wallet_transactions'
    }
  );

WalletTransactionSchema.index(
  {
    reference_type: 1,
    reference_id: 1,
    type: 1
  },
  {
    unique: true,
    sparse: true
  }
);

const WalletTransaction =
  mongoose.model(
    'WalletTransaction',
    WalletTransactionSchema
  );


// =====================================================
// PAYMENT
// =====================================================

const PaymentSchema =
  new mongoose.Schema(
    {
      user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
      },

      plan: {
        type: String,
        default: null
      },

      amount: {
        type: Number,
        required: true
      },

      currency: {
        type: String,
        default: 'INR'
      },

      merchant_order_id: {
        type: String,
        unique: true,
        required: true,
        index: true
      },

      platform_order_id: {
        type: String,
        default: null,
        index: true
      },

      pay_url: {
        type: String,
        default: null
      },

      gateway: {
        type: String,
        default: 'WATCHPAYS'
      },

      status: {
        type: String,
        default: 'created',
        index: true
      },

      created_at: {
        type: Date,
        default: Date.now
      },

      paid_at: {
        type: Date,
        default: null
      }
    },
    {
      collection: 'payments'
    }
  );

const Payment =
  mongoose.model(
    'Payment',
    PaymentSchema
  );


// =====================================================
// WITHDRAWAL
// =====================================================

const WithdrawalSchema =
  new mongoose.Schema(
    {
      user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
      },

      amount: {
        type: Number,
        required: true
      },

      currency: {
        type: String,
        default: 'INR'
      },

      method: {
        type: String,
        enum: [
          'UPI',
          'BANK'
        ],
        required: true
      },

      upi_id: {
        type: String,
        default: null
      },

      account_name: {
        type: String,
        default: null
      },

      account_number: {
        type: String,
        default: null
      },

      account_last4: {
        type: String,
        default: null
      },

      ifsc: {
        type: String,
        default: null
      },

      bank_name: {
        type: String,
        default: null
      },

      gateway: {
        type: String,
        default: null
      },

      gateway_transaction_id: {
        type: String,
        default: null,
        index: true
      },

      gateway_fee: {
        type: Number,
        default: 0
      },

      status: {
        type: String,
        enum: [
          'pending',
          'processing',
          'completed',
          'rejected'
        ],
        default: 'pending',
        index: true
      },

      created_at: {
        type: Date,
        default: Date.now
      },

      processed_at: {
        type: Date,
        default: null
      }
    },
    {
      collection: 'withdrawals'
    }
  );

const Withdrawal =
  mongoose.model(
    'Withdrawal',
    WithdrawalSchema
  );


// =====================================================
// PLAN
// =====================================================

const PlanSchema =
  new mongoose.Schema(
    {
      name: String,

      amount: Number,

      duration_days: Number,

      daily_return: Number,

      total_return: Number,

      active: {
        type: Boolean,
        default: true
      },

      created_at: {
        type: Date,
        default: Date.now
      }
    },
    {
      collection: 'plans'
    }
  );

const Plan =
  mongoose.model(
    'Plan',
    PlanSchema
  );


// =====================================================
// INVESTMENT
// =====================================================

const InvestmentSchema =
  new mongoose.Schema(
    {
      user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
      },

      plan_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Plan',
        default: null
      },

      plan_name: {
        type: String,
        default: null
      },

      amount: Number,

      status: {
        type: String,
        default: 'active'
      },

      started_at: {
        type: Date,
        default: Date.now
      },

      expires_at: {
        type: Date,
        default: null
      }
    },
    {
      collection: 'investments'
    }
  );

const Investment =
  mongoose.model(
    'Investment',
    InvestmentSchema
  );


// =====================================================
// NOTIFICATION
// =====================================================

const NotificationSchema =
  new mongoose.Schema(
    {
      user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
      },

      title: {
        type: String,
        required: true
      },

      message: {
        type: String,
        required: true
      },

      read: {
        type: Boolean,
        default: false
      },

      created_at: {
        type: Date,
        default: Date.now
      }
    },
    {
      collection: 'notifications'
    }
  );

const Notification =
  mongoose.model(
    'Notification',
    NotificationSchema
  );


// =====================================================
// PLATFORM SETTINGS
// =====================================================

const PlatformSettingsSchema =
  new mongoose.Schema(
    {
      key: {
        type: String,
        unique: true,
        required: true
      },

      value: mongoose.Schema.Types.Mixed,

      updated_at: {
        type: Date,
        default: Date.now
      }
    },
    {
      collection:
        'platform_settings'
    }
  );

const PlatformSettings =
  mongoose.model(
    'PlatformSettings',
    PlatformSettingsSchema
  );


// =====================================================
// ADMIN ACTIVITY
// =====================================================

const AdminActivitySchema =
  new mongoose.Schema(
    {
      action: String,

      admin: String,

      details:
        mongoose.Schema.Types.Mixed,

      created_at: {
        type: Date,
        default: Date.now
      }
    },
    {
      collection:
        'admin_activity'
    }
  );

const AdminActivity =
  mongoose.model(
    'AdminActivity',
    AdminActivitySchema
  );


// =====================================================
// WALLET HELPER
// =====================================================

async function ensureWallet(
  userId,
  mongoSession = null
) {
  let wallet =
    await Wallet.findOne({
      user_id: userId
    }).session(
      mongoSession || null
    );

  if (!wallet) {
    try {
      const created =
        await Wallet.create(
          [
            {
              user_id: userId,
              balance: 0,
              updated_at:
                new Date()
            }
          ],
          mongoSession
            ? {
                session:
                  mongoSession
              }
            : undefined
        );

      wallet =
        created[0];
    } catch (error) {
      if (
        error.code === 11000
      ) {
        wallet =
          await Wallet.findOne({
            user_id: userId
          }).session(
            mongoSession || null
          );
      } else {
        throw error;
      }
    }
  }

  return wallet;
}


// =====================================================
// SAFE USER
// =====================================================

function safeUser(user) {
  if (!user) {
    return null;
  }

  return {
    id:
      user._id,

    name:
      user.name,

    phone:
      user.phone,

    referral_code:
      user.referral_code,

    referred_by:
      user.referred_by,

    banned:
      user.banned === true,

    vip_level:
      user.vip_level || 0,

    created_at:
      user.created_at
  };
}


// =====================================================
// LOGIN MIDDLEWARE
// =====================================================

async function login(
  req,
  res,
  next
) {
  try {
    if (
      !req.session ||
      !req.session.userId ||
      req.session.isAdmin
    ) {
      return res.status(401).json({
        success: false,
        message:
          'Login required.'
      });
    }

    const user =
      await User.findById(
        req.session.userId
      );

    if (!user) {
      return res.status(401).json({
        success: false,
        message:
          'User not found.'
      });
    }

    if (user.banned) {
      return res.status(403).json({
        success: false,
        message:
          'Account is banned.'
      });
    }

    req.user = user;

    next();
  } catch (error) {
    next(error);
  }
}


// =====================================================
// ADMIN MIDDLEWARE
// =====================================================

function admin(
  req,
  res,
  next
) {
  if (
    !req.session ||
    req.session.isAdmin !== true
  ) {
    return res.status(401).json({
      success: false,
      message:
        'Admin login required.'
    });
  }

  next();
}


// =====================================================
// SESSION
// =====================================================

if (!MONGO_URI) {
  console.error(
    'MONGODB_URI / MONGO_URI is missing.'
  );
}

app.use(
  session({
    name: 'nove.sid',

    secret:
      SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    store:
      MongoStore.create({
        mongoUrl:
          MONGO_URI,

        ttl:
          60 * 60 * 24 * 14
      }),

    cookie: {
      maxAge:
        1000 *
        60 *
        60 *
        24 *
        14,

      httpOnly: true,

      secure:
        process.env.NODE_ENV ===
        'production',

      sameSite:
        process.env.NODE_ENV ===
        'production'
          ? 'none'
          : 'lax'
    }
  })
);


// =====================================================
// REGISTER
// =====================================================

app.post(
  '/api/register',
  async (req, res) => {
    try {
      const name =
        String(
          req.body.name || ''
        ).trim();

      const phone =
        String(
          req.body.phone ||
          req.body.mobile ||
          ''
        ).trim();

      const password =
        String(
          req.body.password || ''
        );

      const referral =
  String(
    req.body.referral ||
    req.body.referral_code ||
    ''
  )
    .trim()
    .toUpperCase();

      if (!phone) {
        return res.status(400).json({
          success: false,
          message:
            'Mobile number is required.'
        });
      }

      if (
        password.length < 4
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Password must be at least 4 characters.'
        });
      }

      const existing =
        await User.findOne({
          phone
        });

      if (existing) {
        return res.status(409).json({
          success: false,
          message:
            'Mobile number already registered.'
        });
      }

      let referralCode;

      for (let i = 0; i < 10; i++) {
        const candidate =
          (
            'NOVA' +
            crypto
              .randomBytes(4)
              .toString('hex')
          ).toUpperCase();

        const exists =
          await User.findOne({
            referral_code:
              candidate
          });

        if (!exists) {
          referralCode =
            candidate;
          break;
        }
      }

      if (!referralCode) {
        throw new Error(
          'Unable to generate referral code.'
        );
      }

      const salt =
        createSalt();

      const passwordHash =
        hashPassword(
          password,
          salt
        );

      const user = await User.create({
  name,
  phone,
  salt,
  password_hash: passwordHash,
  referral_code: referralCode,
  referred_by: referral || null
});

      await ensureWallet(
        user._id
      );

      res.json({
        success: true,

        message:
          'Registration successful.',

        user:
          safeUser(user)
      });
    } catch (error) {
      console.error(
        'Register error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Unable to register.'
      });
    }
  }
);


// =====================================================
// LOGIN
// =====================================================

app.post(
  '/api/login',
  async (req, res) => {
    try {
      const phone =
        String(
          req.body.phone ||
          req.body.mobile ||
          ''
        ).trim();

      const password =
        String(
          req.body.password || ''
        );

      const user =
        await User.findOne({
          phone
        });

      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            'Invalid mobile or password.'
        });
      }

      if (user.banned) {
        return res.status(403).json({
          success: false,
          message:
            'Account is banned.'
        });
      }

      if (
        !verifyPassword(
          password,
          user.salt,
          user.password_hash
        )
      ) {
        return res.status(401).json({
          success: false,
          message:
            'Invalid mobile or password.'
        });
      }

      req.session.regenerate(
        error => {
          if (error) {
            return res.status(500).json({
              success: false,
              message:
                'Unable to create session.'
            });
          }

          req.session.userId =
            user._id.toString();

          req.session.isAdmin =
            false;

          req.session.save(
            saveError => {
              if (saveError) {
                return res.status(500).json({
                  success: false,
                  message:
                    'Unable to save session.'
                });
              }

              res.json({
                success: true,

                message:
                  'Login successful.',

                user:
                  safeUser(user)
              });
            }
          );
        }
      );
    } catch (error) {
      console.error(
        'Login error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Login failed.'
      });
    }
  }
);


// =====================================================
// ME
// =====================================================

app.get(
  '/api/me',
  login,
  async (req, res) => {
    res.json({
      success: true,

      user:
        safeUser(req.user)
    });
  }
);


// =====================================================
// WALLET
// =====================================================

app.get(
  '/api/wallet',
  login,
  async (req, res) => {
    try {
      const wallet =
        await ensureWallet(
          req.session.userId
        );

      res.json({
        success: true,

        balance:
          paiseToMoney(
            wallet.balance
          )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load wallet.'
      });
    }
  }
);


// =====================================================
// REFERRAL
// =====================================================

app.get(
  '/api/referral',
  login,
  async (req, res) => {
    try {
      const referralCode =
        String(
          req.user.referral_code || ''
        )
          .trim()
          .toUpperCase();

      const referrals =
        await User.countDocuments({
          $expr: {
            $eq: [
              {
                $toUpper: {
                  $ifNull: [
                    '$referred_by',
                    ''
                  ]
                }
              },
              referralCode
            ]
          }
        });

      res.json({
        success: true,

        referral_code:
          referralCode,

        referral_count:
          referrals
      });

    } catch (error) {

      console.error(
        'Referral count error:',
        error
      );

      res.status(500).json({
        success: false,

        message:
          'Unable to load referral.'
      });
    }
  }
);

app.get(
  '/api/referrals',
  login,
  async (req, res) => {
    try {
      const referralCode =
        String(
          req.user.referral_code || ''
        )
          .trim()
          .toUpperCase();

      const users =
        await User.find({
          $expr: {
            $eq: [
              {
                $toUpper: {
                  $ifNull: [
                    '$referred_by',
                    ''
                  ]
                }
              },
              referralCode
            ]
          }
        })
        .select(
          'name phone created_at'
        )
        .sort({
          created_at: -1
        })
        .lean();

      res.json({
        success: true,

        referrals:
          users
      });

    } catch (error) {

      console.error(
        'Referral users error:',
        error
      );

      res.status(500).json({
        success: false,

        message:
          'Unable to load referrals.'
      });
    }
  }
);


// =====================================================
// WATCHPAYS PAY-IN CREATE
// =====================================================

app.post(
  '/api/watchpays/create-order',
  login,
  async (req, res) => {
    try {
      if (
        !WATCHPAYS_MERCHANT_ID ||
        !WATCHPAYS_API_KEY
      ) {
        return res.status(500).json({
          success: false,
          message:
            'WatchPays Pay-in is not configured.'
        });
      }

      if (
        !WATCHPAYS_PAYIN_CALLBACK
      ) {
        return res.status(500).json({
          success: false,
          message:
            'WatchPays callback URL is not configured.'
        });
      }

      const amount =
        Number(
          req.body.amount
        );

      const plan =
        req.body.plan ||
        null;

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid payment amount.'
        });
      }

      if (amount < 1) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid payment amount.'
        });
      }

      const merchantOrderNo =
        makeRef('WP');

      const amountString =
        amount.toFixed(2);

      const signature =
        watchPayinSignature({
          merchant_id:
            WATCHPAYS_MERCHANT_ID,

          amount:
            amountString,

          merchant_order_no:
            merchantOrderNo,

          callback_url:
            WATCHPAYS_PAYIN_CALLBACK
        });

      const body = {
        merchant_id:
          WATCHPAYS_MERCHANT_ID,

        api_key:
          WATCHPAYS_API_KEY,

        amount:
          amountString,

        merchant_order_no:
          merchantOrderNo,

        callback_url:
          WATCHPAYS_PAYIN_CALLBACK,

        signature
      };

      if (
        req.body.extra !== undefined
      ) {
        body.extra =
          String(
            req.body.extra
          );
      }

      const response =
        await fetch(
          WATCHPAYS_PAYIN_URL,
          {
            method: 'POST',

            headers: {
              'Content-Type':
                'application/json',

              Accept:
                'application/json'
            },

            body:
              JSON.stringify(body)
          }
        );

      const text =
        await response.text();

      let result;

      try {
        result =
          JSON.parse(text);
      } catch {
        result = {
          raw: text
        };
      }

      console.log(
        'WatchPays Pay-in response:',
        {
          status:
            response.status,

          success:
            result?.success,

          merchant_order_no:
            result?.merchant_order_no,

          order_no:
            result?.order_no
        }
      );

      if (
        !response.ok ||
        result?.success !== true ||
        !result?.payment_url
      ) {
        return res.status(400).json({
          success: false,

          message:
            result?.message ||
            'WatchPays payment creation failed.'
        });
      }

      const payment =
        await Payment.create({
          user_id:
            req.session.userId,

          plan:
            plan || null,

          amount:
            moneyToPaise(amount),

          currency:
            'INR',

          merchant_order_id:
            merchantOrderNo,

          platform_order_id:
            result.order_no ||
            null,

          pay_url:
            result.payment_url,

          gateway:
            'WATCHPAYS',

          status:
            result.status ||
            'created'
        });

      return res.json({
        success: true,

        paymentId:
          payment._id,

        merchant_order_no:
          merchantOrderNo,

        order_no:
          result.order_no ||
          null,

        payment_url:
          result.payment_url,

        payUrl:
          result.payment_url,

        amount
      });
    } catch (error) {
      console.error(
        'WatchPays Pay-in create error:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Unable to create WatchPays payment.'
      });
    }
  }
);


// =====================================================
// WATCHPAYS PAY-IN CALLBACK
// =====================================================

app.post(
  '/api/watchpays/callback',
  async (req, res) => {
    try {
      console.log(
        'WatchPays Pay-in callback:',
        req.body
      );

      const {
        orderNo,
        merchantOrder,
        status,
        amount
      } = req.body;

      if (!merchantOrder) {
        return res.status(400).send(
          'merchantOrder missing'
        );
      }

      const payment =
        await Payment.findOne({
          merchant_order_id:
            merchantOrder,

          gateway:
            'WATCHPAYS'
        });

      if (!payment) {
        return res.status(404).send(
          'order not found'
        );
      }

      if (
        payment.status === 'paid' ||
        payment.status === 'captured'
      ) {
        return res.send(
          'success'
        );
      }

      if (
        String(status || '')
          .toLowerCase() !==
        'success'
      ) {
        payment.status =
          String(
            status || 'failed'
          ).toLowerCase();

        await payment.save();

        return res.send(
          'success'
        );
      }

      const callbackAmount =
        Number(amount);

      const expectedAmount =
        paiseToMoney(
          payment.amount
        );

      if (
        !Number.isFinite(
          callbackAmount
        ) ||
        Math.abs(
          callbackAmount -
          expectedAmount
        ) > 0.01
      ) {
        console.error(
          'WatchPays amount mismatch:',
          {
            callbackAmount,
            expectedAmount
          }
        );

        return res.status(400).send(
          'amount mismatch'
        );
      }

      const mongoSession =
        await mongoose.startSession();

      try {
        await mongoSession.withTransaction(
          async () => {
            const fresh =
              await Payment.findById(
                payment._id
              ).session(
                mongoSession
              );

            if (!fresh) {
              throw new Error(
                'Payment not found.'
              );
            }

            if (
              fresh.status === 'paid' ||
              fresh.status === 'captured'
            ) {
              return;
            }

            const wallet =
              await ensureWallet(
                fresh.user_id,
                mongoSession
              );

            const oldBalance =
              Number(
                wallet.balance || 0
              );

            const credit =
              Number(
                fresh.amount
              );

            const newBalance =
              oldBalance +
              credit;

            wallet.balance =
              newBalance;

            wallet.updated_at =
              new Date();

            await wallet.save({
              session:
                mongoSession
            });

            try {
              await WalletTransaction.create(
                [
                  {
                    user_id:
                      fresh.user_id,

                    type:
                      'credit',

                    amount:
                      credit,

                    balance_after:
                      newBalance,

                    reference_type:
                      'watchpays_payment',

                    reference_id:
                      String(
                        fresh._id
                      ),

                    created_at:
                      new Date()
                  }
                ],
                {
                  session:
                    mongoSession
                }
              );
            } catch (transactionError) {
              if (
                transactionError.code ===
                11000
              ) {
                return;
              }

              throw transactionError;
            }

            fresh.status =
              'paid';

            fresh.paid_at =
              new Date();

            fresh.platform_order_id =
              orderNo ||
              fresh.platform_order_id ||
              null;

            await fresh.save({
              session:
                mongoSession
            });
          }
        );
      } finally {
        await mongoSession.endSession();
      }

      return res.send(
        'success'
      );
    } catch (error) {
      console.error(
        'WatchPays callback error:',
        error
      );

      return res.status(500).send(
        'callback error'
      );
    }
  }
);


// =====================================================
// WATCHPAYS PAYOUT
// =====================================================

async function sendWatchPayout(
  withdrawal
) {
  if (
    !WATCHPAYS_MERCHANT_ID ||
    !WATCHPAYS_PAYOUT_KEY
  ) {
    throw new Error(
      'WatchPays Payout is not configured.'
    );
  }

  if (!WATCHPAYS_PAYOUT_CALLBACK) {
    throw new Error(
      'WatchPays Payout callback URL is not configured.'
    );
  }

  if (
    String(
      withdrawal.method
    ).toUpperCase() !==
    'BANK'
  ) {
    throw new Error(
      'WatchPays payout integration supports BANK withdrawals only.'
    );
  }

  if (
    !withdrawal.account_number ||
    !withdrawal.ifsc ||
    !withdrawal.account_name
  ) {
    throw new Error(
      'Bank details are incomplete.'
    );
  }

  const transactionId =
    `WPW_${String(
      withdrawal._id
    )}`;

  const amount =
    paiseToMoney(
      withdrawal.amount
    );

  const amountString =
    amount.toFixed(2);

  const signature =
    watchPayoutSignature({
      merchant_id:
        WATCHPAYS_MERCHANT_ID,

      amount:
        amountString,

      transaction_id:
        transactionId,

      account_number:
        withdrawal.account_number,

      ifsc:
        withdrawal.ifsc,

      name:
        withdrawal.account_name,

      bank_name:
        withdrawal.bank_name ||
        '',

      callback_url:
        WATCHPAYS_PAYOUT_CALLBACK
    });

  const form =
    new URLSearchParams();

  form.set(
    'merchant_id',
    WATCHPAYS_MERCHANT_ID
  );

  form.set(
    'amount',
    amountString
  );

  form.set(
    'transaction_id',
    transactionId
  );

  form.set(
    'account_number',
    withdrawal.account_number
  );

  form.set(
    'ifsc',
    withdrawal.ifsc
  );

  form.set(
    'name',
    withdrawal.account_name
  );

  form.set(
    'bank_name',
    withdrawal.bank_name || ''
  );

  form.set(
    'callback_url',
    WATCHPAYS_PAYOUT_CALLBACK
  );

  form.set(
    'signature',
    signature
  );

  const response =
    await fetch(
      WATCHPAYS_PAYOUT_URL,
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded',

          Accept:
            'application/json'
        },

        body:
          form.toString()
      }
    );

  const text =
    await response.text();

  let result;

  try {
    result =
      JSON.parse(text);
  } catch {
    result = {
      raw: text
    };
  }

  console.log(
    'WatchPays Payout response:',
    {
      status:
        response.status,

      gatewayStatus:
        result?.status,

      transaction_id:
        result?.data?.transaction_id
    }
  );

  if (
    !response.ok ||
    result?.status !== 'success'
  ) {
    throw new Error(
      result?.message ||
      'WatchPays payout request failed.'
    );
  }

  return {
    transactionId,

    amount,

    fee:
      Number(
        result?.data?.fee || 0
      ),

    totalAmount:
      Number(
        result?.data?.total_amount ||
        amount
      ),

    response:
      result
  };
}


// =====================================================
// WATCHPAYS PAYOUT CALLBACK
// =====================================================

app.post(
  '/api/watchpays/payout-callback',
  async (req, res) => {
    try {
      console.log(
        'WatchPays Payout callback:',
        req.body
      );

      const {
        merchant_id,
        transaction_id,
        amount,
        status
      } = req.body;

      if (
        String(merchant_id || '') !==
        String(
          WATCHPAYS_MERCHANT_ID
        )
      ) {
        return res.status(403).send(
          'invalid merchant'
        );
      }

      if (!transaction_id) {
        return res.status(400).send(
          'transaction_id missing'
        );
      }

      if (
        !String(
          transaction_id
        ).startsWith('WPW_')
      ) {
        return res.status(400).send(
          'invalid transaction'
        );
      }

      const withdrawalId =
        String(
          transaction_id
        ).replace(
          /^WPW_/,
          ''
        );

      if (
        !mongoose.isValidObjectId(
          withdrawalId
        )
      ) {
        return res.status(400).send(
          'invalid withdrawal'
        );
      }

      const withdrawal =
        await Withdrawal.findById(
          withdrawalId
        );

      if (!withdrawal) {
        return res.status(404).send(
          'withdrawal not found'
        );
      }

      const callbackAmount =
        Number(amount);

      const expectedAmount =
        paiseToMoney(
          withdrawal.amount
        );

      if (
        !Number.isFinite(
          callbackAmount
        ) ||
        Math.abs(
          callbackAmount -
          expectedAmount
        ) > 0.01
      ) {
        return res.status(400).send(
          'amount mismatch'
        );
      }

      const normalizedStatus =
        String(
          status || ''
        ).toUpperCase();

      if (
        normalizedStatus ===
        'SUCCESS'
      ) {
        withdrawal.status =
          'completed';

        withdrawal.gateway =
          'WATCHPAYS';

        withdrawal.gateway_transaction_id =
          transaction_id;

        withdrawal.processed_at =
          new Date();

        await withdrawal.save();

        return res.send(
          'success'
        );
      }

      if (
        normalizedStatus ===
        'FAILED'
      ) {
        const mongoSession =
          await mongoose.startSession();

        try {
          await mongoSession.withTransaction(
            async () => {
              const fresh =
                await Withdrawal.findById(
                  withdrawal._id
                ).session(
                  mongoSession
                );

              if (!fresh) {
                throw new Error(
                  'Withdrawal not found.'
                );
              }

              if (
                fresh.status ===
                'completed'
              ) {
                return;
              }

              if (
                fresh.status ===
                'rejected'
              ) {
                return;
              }

              const wallet =
                await ensureWallet(
                  fresh.user_id,
                  mongoSession
                );

              const oldBalance =
                Number(
                  wallet.balance || 0
                );

              const newBalance =
                oldBalance +
                Number(
                  fresh.amount
                );

              wallet.balance =
                newBalance;

              wallet.updated_at =
                new Date();

              await wallet.save({
                session:
                  mongoSession
              });

              try {
                await WalletTransaction.create(
                  [
                    {
                      user_id:
                        fresh.user_id,

                      type:
                        'refund',

                      amount:
                        fresh.amount,

                      balance_after:
                        newBalance,

                      reference_type:
                        'watchpays_payout_failed',

                      reference_id:
                        String(
                          fresh._id
                        ),

                      created_at:
                        new Date()
                    }
                  ],
                  {
                    session:
                      mongoSession
                  }
                );
              } catch (transactionError) {
                if (
                  transactionError.code ===
                  11000
                ) {
                  return;
                }

                throw transactionError;
              }

              fresh.status =
                'rejected';

              fresh.gateway =
                'WATCHPAYS';

              fresh.gateway_transaction_id =
                transaction_id;

              fresh.processed_at =
                new Date();

              await fresh.save({
                session:
                  mongoSession
              });
            }
          );
        } finally {
          await mongoSession.endSession();
        }

        return res.send(
          'success'
        );
      }

      return res.send(
        'success'
      );
    } catch (error) {
      console.error(
        'WatchPays payout callback error:',
        error
      );

      return res.status(500).send(
        'callback error'
      );
    }
  }
);


// =====================================================
// PAYMENT STATUS
// =====================================================

app.get(
  '/api/payment/status/:orderId',
  login,
  async (req, res) => {
    try {
      const payment =
        await Payment.findOne({
          _id:
            mongoose.isValidObjectId(
              req.params.orderId
            )
              ? req.params.orderId
              : null,

          user_id:
            req.session.userId
        }).lean();

      if (!payment) {
        return res.status(404).json({
          success: false,
          message:
            'Payment not found.'
        });
      }

      res.json({
        success: true,

        status:
          payment.status,

        amount:
          paiseToMoney(
            payment.amount
          ),

        gateway:
          payment.gateway,

        merchant_order_id:
          payment.merchant_order_id,

        platform_order_id:
          payment.platform_order_id
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load payment status.'
      });
    }
  }
);


// =====================================================
// ORDERS
// =====================================================

app.get(
  '/api/orders',
  login,
  async (req, res) => {
    try {
      const payments =
        await Payment.find({
          user_id:
            req.session.userId
        })
        .sort({
          created_at: -1
        })
        .lean();

      res.json({
        success: true,

        orders:
          payments.map(
            p => ({
              id:
                p._id,

              plan:
                p.plan,

              amount:
                paiseToMoney(
                  p.amount
                ),

              currency:
                p.currency,

              merchant_order_id:
                p.merchant_order_id,

              platform_order_id:
                p.platform_order_id,

              gateway:
                p.gateway,

              status:
                p.status,

              created_at:
                p.created_at,

              paid_at:
                p.paid_at
            })
          )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load orders.'
      });
    }
  }
);


// =====================================================
// WITHDRAWAL REQUEST
// =====================================================

app.post(
  '/api/withdrawals',
  login,
  async (req, res) => {
    let mongoSession = null;

    try {
      const amount =
        Number(
          req.body.amount
        );

      const method =
        String(
          req.body.method ||
          req.body.withdrawalMethod ||
          'BANK'
        )
        .trim()
        .toUpperCase();

      const upiId =
        String(
          req.body.upi_id ||
          req.body.upiId ||
          ''
        ).trim();

      const accountName =
        String(
          req.body.account_name ||
          req.body.accountName ||
          ''
        ).trim();

      const accountNumber =
        String(
          req.body.account_number ||
          req.body.accountNumber ||
          ''
        ).trim();

      const confirmAccountNumber =
        String(
          req.body.confirm_account_number ||
          req.body.confirmAccountNumber ||
          req.body.confirm_account ||
          ''
        ).trim();

      const bankName =
        String(
          req.body.bank_name ||
          req.body.bankName ||
          ''
        ).trim();

      const ifsc =
        String(
          req.body.ifsc ||
          req.body.IFSC ||
          ''
        )
        .trim()
        .toUpperCase();

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid withdrawal amount.'
        });
      }

      if (amount < 50) {
        return res.status(400).json({
          success: false,
          message:
            'Minimum withdrawal amount is ₹50.'
        });
      }

      if (
        ![
          'UPI',
          'BANK'
        ].includes(method)
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid withdrawal method.'
        });
      }

      if (
        method === 'UPI' &&
        !upiId
      ) {
        return res.status(400).json({
          success: false,
          message:
            'UPI ID is required.'
        });
      }

      if (
        method === 'BANK'
      ) {
        if (!accountName) {
          return res.status(400).json({
            success: false,
            message:
              'Account holder name is required.'
          });
        }

        if (!accountNumber) {
          return res.status(400).json({
            success: false,
            message:
              'Bank account number is required.'
          });
        }

        if (
          confirmAccountNumber &&
          accountNumber !==
            confirmAccountNumber
        ) {
          return res.status(400).json({
            success: false,
            message:
              'Bank account numbers do not match.'
          });
        }

        if (!ifsc) {
          return res.status(400).json({
            success: false,
            message:
              'IFSC code is required.'
          });
        }

        if (
          !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(
            ifsc
          )
        ) {
          return res.status(400).json({
            success: false,
            message:
              'Invalid IFSC code.'
          });
        }
      }

      const amountPaise =
        moneyToPaise(amount);

      mongoSession =
        await mongoose.startSession();

      let withdrawal;

      await mongoSession.withTransaction(
        async () => {
          const wallet =
            await ensureWallet(
              req.session.userId,
              mongoSession
            );

          const balance =
            Number(
              wallet.balance || 0
            );

          if (
            balance <
            amountPaise
          ) {
            throw new Error(
              'Insufficient wallet balance.'
            );
          }

          const newBalance =
            balance -
            amountPaise;

          wallet.balance =
            newBalance;

          wallet.updated_at =
            new Date();

          await wallet.save({
            session:
              mongoSession
          });

          const created =
            await Withdrawal.create(
              [
                {
                  user_id:
                    req.session.userId,

                  amount:
                    amountPaise,

                  currency:
                    'INR',

                  method,

                  upi_id:
                    method === 'UPI'
                      ? upiId
                      : null,

                  account_name:
                    method === 'BANK'
                      ? accountName
                      : null,

                  account_number:
                    method === 'BANK'
                      ? accountNumber
                      : null,

                  account_last4:
                    method === 'BANK'
                      ? accountNumber.slice(-4)
                      : null,

                  bank_name:
                    method === 'BANK'
                      ? bankName
                      : null,

                  ifsc:
                    method === 'BANK'
                      ? ifsc
                      : null,

                  status:
                    'pending',

                  created_at:
                    new Date()
                }
              ],
              {
                session:
                  mongoSession
              }
            );

          withdrawal =
            created[0];

          await WalletTransaction.create(
            [
              {
                user_id:
                  req.session.userId,

                type:
                  'debit',

                amount:
                  amountPaise,

                balance_after:
                  newBalance,

                reference_type:
                  'withdrawal',

                reference_id:
                  String(
                    withdrawal._id
                  )
              }
            ],
            {
              session:
                mongoSession
            }
          );
        }
      );

      return res.json({
        success: true,

        message:
          'Withdrawal request submitted successfully.',

        withdrawal: {
          id:
            withdrawal._id,

          amount,

          method,

          status:
            withdrawal.status
        }
      });
    } catch (error) {
      console.error(
        'Withdrawal error:',
        error
      );

      return res.status(400).json({
        success: false,
        message:
          error.message ||
          'Unable to submit withdrawal.'
      });
    } finally {
      if (mongoSession) {
        await mongoSession
          .endSession()
          .catch(() => {});
      }
    }
  }
);


// =====================================================
// USER WITHDRAWAL HISTORY
// =====================================================

app.get(
  '/api/withdrawals',
  login,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find({
          user_id:
            req.session.userId
        })
        .sort({
          created_at: -1
        })
        .lean();

      res.json({
        success: true,

        withdrawals:
          withdrawals.map(
            w => ({
              id:
                w._id,

              amount:
                paiseToMoney(
                  w.amount
                ),

              currency:
                w.currency,

              method:
                w.method,

              upi_id:
                w.upi_id,

              account_name:
                w.account_name,

              account_last4:
                w.account_last4,

              ifsc:
                w.ifsc,

              bank_name:
                w.bank_name,

              gateway:
                w.gateway,

              gateway_transaction_id:
                w.gateway_transaction_id,

              status:
                w.status,

              created_at:
                w.created_at,

              processed_at:
                w.processed_at
            })
          )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load withdrawals.'
      });
    }
  }
);


// =====================================================
// ADMIN LOGIN
// =====================================================

app.post(
  '/api/admin/login',
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ''
        ).trim();

      const password =
        String(
          req.body.password || ''
        );

      if (
        !ADMIN_USERNAME ||
        !ADMIN_PASSWORD
      ) {
        return res.status(500).json({
          success: false,
          message:
            'Admin credentials are not configured.'
        });
      }

      if (
        username !==
          ADMIN_USERNAME ||
        password !==
          ADMIN_PASSWORD
      ) {
        return res.status(401).json({
          success: false,
          message:
            'Invalid admin credentials.'
        });
      }

      req.session.regenerate(
        error => {
          if (error) {
            return res.status(500).json({
              success: false,
              message:
                'Unable to create admin session.'
            });
          }

          req.session.userId =
            null;

          req.session.isAdmin =
            true;

          req.session.save(
            saveError => {
              if (saveError) {
                return res.status(500).json({
                  success: false,
                  message:
                    'Unable to save admin session.'
                });
              }

              res.json({
                success: true,
                isAdmin: true,
                message:
                  'Admin login successful.'
              });
            }
          );
        }
      );
    } catch (error) {
      console.error(
        'Admin login error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Admin login failed.'
      });
    }
  }
);


// =====================================================
// ADMIN ME
// =====================================================

app.get(
  '/api/admin/me',
  admin,
  (req, res) => {
    res.json({
      success: true,
      isAdmin: true
    });
  }
);


// =====================================================
// ADMIN LOGOUT
// =====================================================

app.post(
  '/api/admin/logout',
  (req, res) => {
    if (!req.session) {
      return res.json({
        success: true
      });
    }

    req.session.isAdmin =
      false;

    req.session.userId =
      null;

    req.session.save(
      error => {
        if (error) {
          return res.status(500).json({
            success: false,
            message:
              'Admin logout failed.'
          });
        }

        res.json({
          success: true,
          message:
            'Admin logged out.'
        });
      }
    );
  }
);


// =====================================================
// ADMIN USERS
// =====================================================

app.get(
  '/api/admin/users',
  admin,
  async (req, res) => {
    try {
      const users =
        await User.find()
          .sort({
            created_at: -1
          })
          .lean();

      const result = [];

      for (
        const user of users
      ) {
        const wallet =
          await Wallet.findOne({
            user_id:
              user._id
          }).lean();

        result.push({
          id:
            user._id,

          name:
            user.name,

          phone:
            user.phone,

          referral_code:
            user.referral_code,

          referred_by:
            user.referred_by,

          balance:
            paiseToMoney(
              wallet?.balance || 0
            ),

          banned:
            user.banned === true,

          vip_level:
            user.vip_level || 0,

          created_at:
            user.created_at
        });
      }

      res.json({
        success: true,
        users: result
      });
    } catch (error) {
      console.error(
        'Admin users error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Unable to load users.'
      });
    }
  }
);


// =====================================================
// BAN
// =====================================================

app.post(
  '/api/admin/users/:userId/ban',
  admin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.params.userId
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            'User not found.'
        });
      }

      user.banned = true;

      await user.save();

      res.json({
        success: true,
        message:
          'User banned successfully.'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to ban user.'
      });
    }
  }
);


// =====================================================
// UNBAN
// =====================================================

app.post(
  '/api/admin/users/:userId/unban',
  admin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.params.userId
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            'User not found.'
        });
      }

      user.banned = false;

      await user.save();

      res.json({
        success: true,
        message:
          'User unbanned successfully.'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to unban user.'
      });
    }
  }
);


// =====================================================
// LOGIN AS USER
// =====================================================

app.post(
  '/api/admin/users/:userId/login-as',
  admin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.params.userId
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            'User not found.'
        });
      }

      if (user.banned) {
        return res.status(403).json({
          success: false,
          message:
            'User is banned.'
        });
      }

      req.session.regenerate(
        error => {
          if (error) {
            return res.status(500).json({
              success: false,
              message:
                'Unable to create session.'
            });
          }

          req.session.userId =
            user._id.toString();

          req.session.isAdmin =
            false;

          req.session.save(
            saveError => {
              if (saveError) {
                return res.status(500).json({
                  success: false,
                  message:
                    'Unable to save session.'
                });
              }

              res.json({
                success: true,
                user:
                  safeUser(user)
              });
            }
          );
        }
      );
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to login as user.'
      });
    }
  }
);


// =====================================================
// ADMIN BALANCE
// =====================================================

app.post(
  '/api/admin/users/:userId/balance',
  admin,
  async (req, res) => {
    const mongoSession =
      await mongoose.startSession();

    try {
      const amount =
        Number(
          req.body.amount
        );

      const type =
        String(
          req.body.type ||
          'credit'
        ).toLowerCase();

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid amount.'
        });
      }

      if (
        ![
          'credit',
          'debit'
        ].includes(type)
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid type.'
        });
      }

      const amountPaise =
        moneyToPaise(amount);

      let finalBalance = 0;

      await mongoSession.withTransaction(
        async () => {
          const user =
            await User.findById(
              req.params.userId
            ).session(
              mongoSession
            );

          if (!user) {
            throw new Error(
              'User not found.'
            );
          }

          const wallet =
            await ensureWallet(
              user._id,
              mongoSession
            );

          const old =
            Number(
              wallet.balance || 0
            );

          if (
            type === 'debit' &&
            old < amountPaise
          ) {
            throw new Error(
              'Insufficient wallet balance.'
            );
          }

          finalBalance =
            type === 'credit'
              ? old + amountPaise
              : old - amountPaise;

          wallet.balance =
            finalBalance;

          wallet.updated_at =
            new Date();

          await wallet.save({
            session:
              mongoSession
          });

          await WalletTransaction.create(
            [
              {
                user_id:
                  user._id,

                type,

                amount:
                  amountPaise,

                balance_after:
                  finalBalance,

                reference_type:
                  'admin_adjustment',

                reference_id:
                  makeRef('ADMIN')
              }
            ],
            {
              session:
                mongoSession
            }
          );
        }
      );

      res.json({
        success: true,

        balance:
          paiseToMoney(
            finalBalance
          )
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message:
          error.message ||
          'Unable to update balance.'
      });
    } finally {
      await mongoSession
        .endSession()
        .catch(() => {});
    }
  }
);


// =====================================================
// ADMIN WITHDRAWALS
// =====================================================

app.get(
  '/api/admin/withdrawals',
  admin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find()
          .populate(
            'user_id',
            'name phone'
          )
          .sort({
            created_at: -1
          })
          .lean();

      res.json({
        success: true,

        withdrawals:
          withdrawals.map(
            w => ({
              id:
                w._id,

              user:
                w.user_id
                  ? {
                      id:
                        w.user_id._id,

                      name:
                        w.user_id.name,

                      phone:
                        w.user_id.phone
                    }
                  : null,

              amount:
                paiseToMoney(
                  w.amount
                ),

              currency:
                w.currency,

              method:
                w.method,

              upi_id:
                w.upi_id,

              account_name:
                w.account_name,

              account_last4:
                w.account_last4,

              ifsc:
                w.ifsc,

              bank_name:
                w.bank_name,

              gateway:
                w.gateway,

              gateway_transaction_id:
                w.gateway_transaction_id,

              gateway_fee:
                paiseToMoney(
                  w.gateway_fee || 0
                ),

              status:
                w.status,

              created_at:
                w.created_at,

              processed_at:
                w.processed_at
            })
          )
      });
    } catch (error) {
      console.error(
        'Admin withdrawals error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Unable to load withdrawals.'
      });
    }
  }
);


// =====================================================
// PROCESS WITHDRAWAL
// =====================================================

async function processWithdrawal(
  req,
  res
) {
  try {
    const withdrawal =
      await Withdrawal.findById(
        req.params.id
      );

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message:
          'Withdrawal not found.'
      });
    }

    if (
      withdrawal.status !==
      'pending'
    ) {
      return res.status(400).json({
        success: false,
        message:
          'Withdrawal cannot be processed.'
      });
    }

    // -------------------------------------------------
    // WATCHPAYS BANK PAYOUT
    // -------------------------------------------------

    if (
      withdrawal.method ===
        'BANK' &&
      WATCHPAYS_MERCHANT_ID &&
      WATCHPAYS_PAYOUT_KEY
    ) {
      if (
        withdrawal.gateway_transaction_id
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Payout has already been submitted.'
        });
      }

      /*
       * IMPORTANT:
       * Gateway call happens BEFORE changing
       * withdrawal status. So if gateway fails,
       * the withdrawal remains pending.
       */

      const payout =
        await sendWatchPayout(
          withdrawal
        );

      withdrawal.status =
        'processing';

      withdrawal.gateway =
        'WATCHPAYS';

      withdrawal.gateway_transaction_id =
        payout.transactionId;

      withdrawal.gateway_fee =
        moneyToPaise(
          payout.fee || 0
        );

      withdrawal.processed_at =
        new Date();

      await withdrawal.save();

      return res.json({
        success: true,

        message:
          'WatchPays payout submitted successfully.',

        gateway:
          'WATCHPAYS',

        transaction_id:
          payout.transactionId,

        amount:
          payout.amount,

        fee:
          payout.fee
      });
    }

    // -------------------------------------------------
    // MANUAL PROCESSING
    // -------------------------------------------------

    withdrawal.status =
      'processing';

    withdrawal.processed_at =
      new Date();

    await withdrawal.save();

    return res.json({
      success: true,

      message:
        'Withdrawal moved to processing.'
    });
  } catch (error) {
    console.error(
      'Process withdrawal error:',
      error
    );

    return res.status(400).json({
      success: false,
      message:
        error.message ||
        'Unable to process withdrawal.'
    });
  }
}

app.post(
  '/api/admin/withdrawals/:id/process',
  admin,
  processWithdrawal
);

app.post(
  '/api/admin/withdrawals/:id/processing',
  admin,
  processWithdrawal
);


// =====================================================
// ADMIN COMPLETE
// =====================================================

app.post(
  '/api/admin/withdrawals/:id/complete',
  admin,
  async (req, res) => {
    try {
      const withdrawal =
        await Withdrawal.findById(
          req.params.id
        );

      if (!withdrawal) {
        return res.status(404).json({
          success: false,
          message:
            'Withdrawal not found.'
        });
      }

      if (
        withdrawal.status !==
        'processing'
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Withdrawal must be processing.'
        });
      }

      withdrawal.status =
        'completed';

      withdrawal.processed_at =
        new Date();

      await withdrawal.save();

      res.json({
        success: true,
        message:
          'Withdrawal completed.'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to complete withdrawal.'
      });
    }
  }
);


// =====================================================
// REJECT + REFUND
// =====================================================

async function rejectWithdrawal(
  req,
  res
) {
  const mongoSession =
    await mongoose.startSession();

  try {
    await mongoSession.withTransaction(
      async () => {
        const withdrawal =
          await Withdrawal.findById(
            req.params.id
          ).session(
            mongoSession
          );

        if (!withdrawal) {
          throw new Error(
            'Withdrawal not found.'
          );
        }

        if (
          withdrawal.status ===
          'completed'
        ) {
          throw new Error(
            'Completed withdrawal cannot be rejected.'
          );
        }

        if (
          withdrawal.status ===
          'processing'
        ) {
          throw new Error(
            'Processing withdrawal should not be manually rejected. Wait for gateway result.'
          );
        }

        if (
          withdrawal.status ===
          'rejected'
        ) {
          return;
        }

        const wallet =
          await ensureWallet(
            withdrawal.user_id,
            mongoSession
          );

        const old =
          Number(
            wallet.balance || 0
          );

        const next =
          old +
          Number(
            withdrawal.amount
          );

        wallet.balance =
          next;

        wallet.updated_at =
          new Date();

        await wallet.save({
          session:
            mongoSession
        });

        try {
          await WalletTransaction.create(
            [
              {
                user_id:
                  withdrawal.user_id,

                type:
                  'refund',

                amount:
                  withdrawal.amount,

                balance_after:
                  next,

                reference_type:
                  'withdrawal_refund',

                reference_id:
                  String(
                    withdrawal._id
                  )
              }
            ],
            {
              session:
                mongoSession
            }
          );
        } catch (transactionError) {
          if (
            transactionError.code ===
            11000
          ) {
            return;
          }

          throw transactionError;
        }

        withdrawal.status =
          'rejected';

        withdrawal.processed_at =
          new Date();

        await withdrawal.save({
          session:
            mongoSession
        });
      }
    );

    res.json({
      success: true,
      message:
        'Withdrawal rejected and amount refunded.'
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message:
        error.message ||
        'Unable to reject withdrawal.'
    });
  } finally {
    await mongoSession
      .endSession()
      .catch(() => {});
  }
}

app.post(
  '/api/admin/withdrawals/:id/reject',
  admin,
  rejectWithdrawal
);

app.post(
  '/api/admin/withdrawals/:id/refund',
  admin,
  rejectWithdrawal
);


// =====================================================
// ADMIN VIP
// =====================================================

app.post(
  '/api/admin/users/:userId/vip',
  admin,
  async (req, res) => {
    try {
      const level =
        Number(
          req.body.vip_level ??
          req.body.level ??
          0
        );

      if (
        !Number.isInteger(level) ||
        level < 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid VIP level.'
        });
      }

      const user =
        await User.findByIdAndUpdate(
          req.params.userId,
          {
            vip_level:
              level
          },
          {
            new: true
          }
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            'User not found.'
        });
      }

      res.json({
        success: true,

        message:
          'VIP level updated.',

        vip_level:
          user.vip_level
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to update VIP.'
      });
    }
  }
);

app.post(
  '/api/admin/users/:userId/vip5',
  admin,
  async (req, res) => {
    try {
      const user =
        await User.findByIdAndUpdate(
          req.params.userId,
          {
            vip_level: 5
          },
          {
            new: true
          }
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            'User not found.'
        });
      }

      res.json({
        success: true,

        message:
          'VIP 5 updated.',

        vip_level:
          user.vip_level
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to update VIP.'
      });
    }
  }
);


// =====================================================
// PLANS
// =====================================================

app.get(
  '/api/plans',
  async (req, res) => {
    try {
      const plans =
        await Plan.find({
          active: true
        })
        .sort({
          amount: 1
        })
        .lean();

      res.json({
        success: true,
        plans
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load plans.'
      });
    }
  }
);


// =====================================================
// ADMIN CREATE PLAN
// =====================================================

app.post(
  '/api/admin/plans',
  admin,
  async (req, res) => {
    try {
      const plan =
        await Plan.create({
          name:
            String(
              req.body.name || ''
            ).trim(),

          amount:
            Number(
              req.body.amount
            ),

          duration_days:
            Number(
              req.body.duration_days ||
              0
            ),

          daily_return:
            Number(
              req.body.daily_return ||
              0
            ),

          total_return:
            Number(
              req.body.total_return ||
              0
            ),

          active:
            req.body.active !== false
        });

      res.json({
        success: true,
        plan
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to create plan.'
      });
    }
  }
);


// =====================================================
// INVESTMENTS
// =====================================================

app.get(
  '/api/investments',
  login,
  async (req, res) => {
    try {
      const investments =
        await Investment.find({
          user_id:
            req.session.userId
        })
        .sort({
          started_at: -1
        })
        .lean();

      res.json({
        success: true,
        investments
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load investments.'
      });
    }
  }
);


app.post(
  '/api/investments',
  login,
  async (req, res) => {
    try {
      const amount =
        Number(
          req.body.amount
        );

      const planId =
        req.body.plan_id ||
        null;

      const plan =
        planId &&
        mongoose.isValidObjectId(
          planId
        )
          ? await Plan.findById(
              planId
            )
          : null;

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid investment amount.'
        });
      }

      const amountPaise =
        moneyToPaise(amount);

      const mongoSession =
        await mongoose.startSession();

      let investment;

      try {
        await mongoSession.withTransaction(
          async () => {
            const wallet =
              await ensureWallet(
                req.session.userId,
                mongoSession
              );

            if (
              wallet.balance <
              amountPaise
            ) {
              throw new Error(
                'Insufficient wallet balance.'
              );
            }

            wallet.balance -=
              amountPaise;

            wallet.updated_at =
              new Date();

            await wallet.save({
              session:
                mongoSession
            });

            const created =
              await Investment.create(
                [
                  {
                    user_id:
                      req.session.userId,

                    plan_id:
                      plan?._id ||
                      null,

                    plan_name:
                      plan?.name ||
                      req.body.plan ||
                      null,

                    amount:
                      amountPaise,

                    status:
                      'active',

                    started_at:
                      new Date(),

                    expires_at:
                      plan?.duration_days
                        ? new Date(
                            Date.now() +
                            plan.duration_days *
                              24 *
                              60 *
                              60 *
                              1000
                          )
                        : null
                  }
                ],
                {
                  session:
                    mongoSession
                }
              );

            investment =
              created[0];

            await WalletTransaction.create(
              [
                {
                  user_id:
                    req.session.userId,

                  type:
                    'debit',

                  amount:
                    amountPaise,

                  balance_after:
                    wallet.balance,

                  reference_type:
                    'investment',

                  reference_id:
                    String(
                      investment._id
                    )
                }
              ],
              {
                session:
                  mongoSession
              }
            );
          }
        );
      } finally {
        await mongoSession.endSession();
      }

      res.json({
        success: true,
        investment
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message:
          error.message ||
          'Unable to create investment.'
      });
    }
  }
);


// =====================================================
// TRANSACTIONS
// =====================================================

app.get(
  '/api/transactions',
  login,
  async (req, res) => {
    try {
      const transactions =
        await WalletTransaction.find({
          user_id:
            req.session.userId
        })
        .sort({
          created_at: -1
        })
        .limit(200)
        .lean();

      res.json({
        success: true,

        transactions:
          transactions.map(
            t => ({
              id:
                t._id,

              type:
                t.type,

              amount:
                paiseToMoney(
                  t.amount
                ),

              balance_after:
                paiseToMoney(
                  t.balance_after
                ),

              reference_type:
                t.reference_type,

              reference_id:
                t.reference_id,

              created_at:
                t.created_at
            })
          )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load transactions.'
      });
    }
  }
);


// =====================================================
// NOTIFICATIONS
// =====================================================

app.get(
  '/api/notifications',
  login,
  async (req, res) => {
    try {
      const notifications =
        await Notification.find({
          user_id:
            req.session.userId
        })
        .sort({
          created_at: -1
        })
        .limit(100)
        .lean();

      res.json({
        success: true,
        notifications
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load notifications.'
      });
    }
  }
);


app.post(
  '/api/notifications/:id/read',
  login,
  async (req, res) => {
    try {
      await Notification.updateOne(
        {
          _id:
            req.params.id,

          user_id:
            req.session.userId
        },
        {
          $set: {
            read: true
          }
        }
      );

      res.json({
        success: true
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to update notification.'
      });
    }
  }
);


// =====================================================
// ADMIN NOTIFICATION
// =====================================================

app.post(
  '/api/admin/notifications',
  admin,
  async (req, res) => {
    try {
      const title =
        String(
          req.body.title || ''
        ).trim();

      const message =
        String(
          req.body.message || ''
        ).trim();

      const userId =
        req.body.user_id ||
        null;

      if (
        !title ||
        !message
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Title and message are required.'
        });
      }

      if (userId) {
        await Notification.create({
          user_id:
            userId,

          title,

          message
        });
      } else {
        const users =
          await User.find()
            .select('_id')
            .lean();

        if (users.length) {
          await Notification.insertMany(
            users.map(
              user => ({
                user_id:
                  user._id,

                title,

                message
              })
            )
          );
        }
      }

      res.json({
        success: true,
        message:
          'Notification sent.'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to send notification.'
      });
    }
  }
);


// =====================================================
// SETTINGS
// =====================================================

app.get(
  '/api/settings',
  async (req, res) => {
    try {
      const settings =
        await PlatformSettings
          .find()
          .lean();

      const result = {};

      for (
        const item of settings
      ) {
        result[item.key] =
          item.value;
      }

      res.json({
        success: true,
        settings:
          result
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load settings.'
      });
    }
  }
);


app.post(
  '/api/admin/settings',
  admin,
  async (req, res) => {
    try {
      const {
        key,
        value
      } = req.body;

      if (!key) {
        return res.status(400).json({
          success: false,
          message:
            'Setting key is required.'
        });
      }

      await PlatformSettings.findOneAndUpdate(
        {
          key:
            String(key)
        },
        {
          key:
            String(key),

          value,

          updated_at:
            new Date()
        },
        {
          upsert: true,
          new: true
        }
      );

      res.json({
        success: true,
        message:
          'Setting updated.'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to update setting.'
      });
    }
  }
);


// =====================================================
// ADMIN SUMMARY
// =====================================================

app.get(
  '/api/admin/summary',
  admin,
  async (req, res) => {
    try {
      const totalUsers =
        await User.countDocuments();

      const walletResult =
        await Wallet.aggregate([
          {
            $group: {
              _id: null,

              total: {
                $sum: {
                  $ifNull: [
                    '$balance',
                    0
                  ]
                }
              }
            }
          }
        ]);

      const totalBalance =
        Number(
          walletResult[0]?.total || 0
        );

      const payments =
        await Payment.aggregate([
          {
            $match: {
              status: {
                $in: [
                  'paid',
                  'captured'
                ]
              }
            }
          },

          {
            $group: {
              _id: null,

              total: {
                $sum: {
                  $ifNull: [
                    '$amount',
                    0
                  ]
                }
              },

              count: {
                $sum: 1
              }
            }
          }
        ]);

      const withdrawals =
        await Withdrawal.aggregate([
          {
            $group: {
              _id:
                '$status',

              amount: {
                $sum: {
                  $ifNull: [
                    '$amount',
                    0
                  ]
                }
              },

              count: {
                $sum: 1
              }
            }
          }
        ]);

      let pending = 0;
      let processing = 0;
      let completed = 0;
      let totalWithdrawn = 0;

      for (
        const row of withdrawals
      ) {
        const status =
          String(
            row._id || ''
          ).toLowerCase();

        if (
          status ===
          'pending'
        ) {
          pending =
            Number(
              row.count
            );
        }

        if (
          status ===
          'processing'
        ) {
          processing =
            Number(
              row.count
            );
        }

        if (
          status ===
          'completed'
        ) {
          completed =
            Number(
              row.count
            );

          totalWithdrawn +=
            Number(
              row.amount || 0
            );
        }
      }

      const totalPayments =
        Number(
          payments[0]?.total || 0
        );

      const successfulPayments =
        Number(
          payments[0]?.count || 0
        );

      res.json({
        success: true,

        total_users:
          totalUsers,

        totalUsers:
          totalUsers,

        totalBalance:
          paiseToMoney(
            totalBalance
          ),

        total_balance:
          paiseToMoney(
            totalBalance
          ),

        totalPayments:
          paiseToMoney(
            totalPayments
          ),

        total_payments:
          paiseToMoney(
            totalPayments
          ),

        totalDeposits:
          paiseToMoney(
            totalPayments
          ),

        total_deposits:
          paiseToMoney(
            totalPayments
          ),

        successful_payments:
          successfulPayments,

        pending,

        pending_withdrawals:
          pending,

        processing,

        processing_withdrawals:
          processing,

        completed_withdrawals:
          completed,

        totalWithdrawn:
          paiseToMoney(
            totalWithdrawn
          ),

        total_withdrawals:
          paiseToMoney(
            totalWithdrawn
          )
      });
    } catch (error) {
      console.error(
        'Summary error:',
        error
      );

      res.status(500).json({
        success: false,
        message:
          'Unable to load summary.'
      });
    }
  }
);


// =====================================================
// TOTAL USERS
// =====================================================

app.get(
  '/api/admin/total-users',
  admin,
  async (req, res) => {
    try {
      const total =
        await User.countDocuments();

      res.json({
        success: true,

        total_users:
          total
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to get users.'
      });
    }
  }
);


// =====================================================
// ADMIN ACTIVITY
// =====================================================

app.get(
  '/api/admin/activity',
  admin,
  async (req, res) => {
    try {
      const activity =
        await AdminActivity.find()
          .sort({
            created_at: -1
          })
          .limit(200)
          .lean();

      res.json({
        success: true,
        activity
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          'Unable to load activity.'
      });
    }
  }
);


// =====================================================
// LOGOUT
// =====================================================

app.post(
  '/api/logout',
  (req, res) => {
    if (!req.session) {
      return res.json({
        success: true
      });
    }

    req.session.destroy(
      error => {
        if (error) {
          return res.status(500).json({
            success: false,
            message:
              'Logout failed.'
          });
        }

        res.clearCookie(
          'nove.sid'
        );

        res.json({
          success: true,

          message:
            'Logged out successfully.'
        });
      }
    );
  }
);


// =====================================================
// STATIC FILES
// =====================================================

app.use(
  express.static(
    __dirname,
    {
      index: false,
      fallthrough: true
    }
  )
);


// =====================================================
// ADMIN STATIC
// =====================================================

app.use(
  '/admin',
  express.static(
    path.join(
      __dirname,
      'admin'
    ),
    {
      index: false,
      fallthrough: false
    }
  )
);


// =====================================================
// ADMIN PAGES
// =====================================================

app.get(
  '/admin.html',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'admin.html'
      )
    );
  }
);


app.get(
  '/admin-dashboard.html',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'admin-dashboard.html'
      )
    );
  }
);


// =====================================================
// ROOT
// =====================================================

app.get(
  '/',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );
  }
);


// =====================================================
// API 404
// =====================================================

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      success: false,

      message:
        'API endpoint not found.'
    });
  }
);


// =====================================================
// ERROR HANDLER
// =====================================================

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      'Unhandled server error:',
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    res.status(500).json({
      success: false,

      message:
        'Internal server error.'
    });
  }
);


// =====================================================
// START SERVER
// =====================================================

async function startServer() {
  try {
    if (!MONGO_URI) {
      throw new Error(
        'MONGODB_URI / MONGO_URI is missing.'
      );
    }

    await mongoose.connect(
      MONGO_URI
    );

    console.log(
      'MongoDB connected successfully.'
    );

    console.log(
      'WatchPays Pay-in:',
      WATCHPAYS_MERCHANT_ID &&
        WATCHPAYS_API_KEY
        ? 'configured'
        : 'NOT configured'
    );

    console.log(
      'WatchPays Payout:',
      WATCHPAYS_MERCHANT_ID &&
        WATCHPAYS_PAYOUT_KEY
        ? 'configured'
        : 'NOT configured'
    );

    app.listen(
      PORT,
      () => {
        console.log(
          `NOVE server running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      'MongoDB connection failed:',
      error
    );

    process.exit(1);
  }
}

startServer();

