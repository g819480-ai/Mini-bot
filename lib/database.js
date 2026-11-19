const mongoose = require('mongoose');
const config = require('../config');

const connectdb = async () => {
    try {
        mongoose.set('strictQuery', false);

        await mongoose.connect(config.MONGODB_URI, {
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
        });

        console.log('✅ Database Connected Successfully');
        return true;
    } catch (e) {
        console.error('❌ Database Connection Failed:', e.message);
        throw e;
    }
};

// ====================================
// BAILEYS BUFFER SERIALIZATION
// ====================================

// Baileys auth data contains Buffers.
// MongoDB/Mongoose must receive those Buffers in a
// predictable form so they can be restored exactly.

function serializeAuthValue(value) {
    if (Buffer.isBuffer(value)) {
        return {
            __scantyType: 'Buffer',
            data: Array.from(value)
        };
    }

    if (value instanceof Uint8Array) {
        return {
            __scantyType: 'Buffer',
            data: Array.from(value)
        };
    }

    if (Array.isArray(value)) {
        return value.map(serializeAuthValue);
    }

    if (value && typeof value === 'object') {
        const result = {};

        for (const [key, item] of Object.entries(value)) {
            result[key] = serializeAuthValue(item);
        }

        return result;
    }

    return value;
}

function deserializeAuthValue(value) {
    if (!value) return value;

    if (
        value &&
        typeof value === 'object' &&
        value.__scantyType === 'Buffer' &&
        Array.isArray(value.data)
    ) {
        return Buffer.from(value.data);
    }

    if (Array.isArray(value)) {
        return value.map(deserializeAuthValue);
    }

    if (value && typeof value === 'object') {
        const result = {};

        for (const [key, item] of Object.entries(value)) {
            result[key] = deserializeAuthValue(item);
        }

        return result;
    }

    return value;
}

// ====================================
// MODÈLES
// ====================================

const sessionSchema = new mongoose.Schema({
    number: {
        type: String,
        required: true,
        unique: true,
        index: true
    },

    // Complete Baileys authentication state.
    //
    // {
    //   creds: {...},
    //   keys: {...}
    // }
    //
    // Stored as Mixed because Baileys auth state contains
    // different nested structures and binary values.
    authState: {
        type: mongoose.Schema.Types.Mixed,
        required: true
    },

    // Kept for compatibility with older records.
    // New code should use authState.
    credentials: {
        type: mongoose.Schema.Types.Mixed,
        required: false
    },

    createdAt: {
        type: Date,
        default: Date.now
    },

    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const userConfigSchema = new mongoose.Schema({
    number: {
        type: String,
        required: true,
        unique: true,
        index: true
    },

    config: {
        AUTO_RECORDING: {
            type: String,
            default: 'false'
        },

        AUTO_TYPING: {
            type: String,
            default: 'false'
        },

        ANTI_CALL: {
            type: String,
            default: 'false'
        },

        REJECT_MSG: {
            type: String,
            default: '*🔕 ʏᴏᴜʀ ᴄᴀʟʟ ᴡᴀs ᴀᴜᴛᴏᴍᴀᴛɪᴄᴀʟʟʏ ʀᴇᴊᴇᴄᴛᴇᴅ..!*'
        },

        READ_MESSAGE: {
            type: String,
            default: 'false'
        },

        AUTO_VIEW_STATUS: {
            type: String,
            default: 'false'
        },

        AUTO_LIKE_STATUS: {
            type: String,
            default: 'false'
        },

        AUTO_STATUS_REPLY: {
            type: String,
            default: 'false'
        },

        AUTO_STATUS_MSG: {
            type: String,
            default: 'Hello from popkid'
        },

        AUTO_LIKE_EMOJI: {
            type: Array,
            default: ['❤️', '👍', '😮', '😎']
        },

        AUTO_REACT: {
            type: String,
            default: 'false'
        },

        AUTO_REACT_EMOJI: {
            type: Array,
            default: [
                '👀',
                '🫀',
                '🧡',
                '❤️‍🩹',
                '❣️',
                '💖',
                '💝',
                '🦋',
                '😘',
                '🤍',
                '🥰',
                '🌝',
                '💨',
                '🌟',
                '✨',
                '🫦',
                '💐',
                '🌺',
                '🪷',
                '🍄',
                '🍁',
                '🪴',
                '🥀',
                '🌈',
                '🌒',
                '🌓',
                '🌔',
                '🌕',
                '🌖',
                '🌗',
                '🌘',
                '🌑',
                '🪽',
                '🍒',
                '🍇',
                '🥖',
                '🥢',
                '🛟',
                '🎀',
                '🎗️',
                '🎈',
                '🎱',
                '🪀',
                '🪄',
                '🪡',
                '🧷',
                '🧣',
                '💍',
                '🧸',
                '🔗',
                '🖇️',
                '🗞️',
                '📅',
                '🔮',
                '♏',
                '🇰🇼',
                '🏳️'
            ]
        }
    },

    createdAt: {
        type: Date,
        default: Date.now
    },

    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const otpSchema = new mongoose.Schema({
    number: {
        type: String,
        required: true,
        index: true
    },

    otp: {
        type: String,
        required: true
    },

    config: {
        type: Object,
        required: true
    },

    expiresAt: {
        type: Date,
        default: () => new Date(Date.now() + 5 * 60000),
        index: {
            expires: '5m'
        }
    },

    createdAt: {
        type: Date,
        default: Date.now
    }
});

// ====================================
// ACTIVE NUMBERS
// ====================================

const activeNumberSchema = new mongoose.Schema({
    number: {
        type: String,
        required: true,
        unique: true,
        index: true
    },

    lastConnected: {
        type: Date,
        default: Date.now
    },

    isActive: {
        type: Boolean,
        default: true
    },

    connectionInfo: {
        ip: String,
        userAgent: String,
        timestamp: Date
    }
});

// ====================================
// STATS
// ====================================

const statsSchema = new mongoose.Schema({
    number: {
        type: String,
        required: true
    },

    date: {
        type: String,
        required: true
    },

    commandsUsed: {
        type: Number,
        default: 0
    },

    messagesReceived: {
        type: Number,
        default: 0
    },

    messagesSent: {
        type: Number,
        default: 0
    },

    groupsInteracted: {
        type: Number,
        default: 0
    }
});

// ====================================
// MODELS
// ====================================

const Session = mongoose.model('Session', sessionSchema);
const UserConfig = mongoose.model('UserConfig', userConfigSchema);
const OTP = mongoose.model('OTP', otpSchema);
const ActiveNumber = mongoose.model('ActiveNumber', activeNumberSchema);
const Stats = mongoose.model('Stats', statsSchema);

// ====================================
// SESSION FUNCTIONS
// ====================================

/**
 * Save the COMPLETE Baileys authentication state.
 *
 * authState must contain:
 *
 * {
 *     creds: state.creds,
 *     keys: state.keys
 * }
 */
async function saveAuthStateToMongoDB(number, authState) {
    try {
        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        if (!authState || typeof authState !== 'object') {
            throw new Error('Invalid Baileys auth state');
        }

        if (!authState.creds) {
            throw new Error('Baileys auth state is missing creds');
        }

        if (!authState.keys) {
            throw new Error('Baileys auth state is missing keys');
        }

        const serialized = serializeAuthValue(authState);

        await Session.findOneAndUpdate(
            { number: cleanNumber },
            {
                authState: serialized,
                updatedAt: new Date()
            },
            {
                upsert: true,
                new: true,
                setDefaultsOnInsert: true
            }
        );

        console.log(`📁 Complete Baileys auth state saved to MongoDB for ${cleanNumber}`);

        return true;

    } catch (error) {
        console.error(
            '❌ Error saving Baileys auth state to MongoDB:',
            error.message
        );

        return false;
    }
}

/**
 * Get the COMPLETE Baileys authentication state.
 */
async function getAuthStateFromMongoDB(number) {
    try {
        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const session = await Session.findOne({
            number: cleanNumber
        }).lean();

        if (!session) {
            return null;
        }

        // New-format session.
        if (session.authState) {
            return deserializeAuthValue(session.authState);
        }

        // Old-format session.
        //
        // This is intentionally returned separately so Nox.js
        // can recognize that it is an old/incomplete session
        // instead of pretending it is a complete Baileys state.
        if (session.credentials) {
            return {
                legacy: true,
                creds: deserializeAuthValue(session.credentials),
                keys: {}
            };
        }

        return null;

    } catch (error) {
        console.error(
            '❌ Error getting Baileys auth state from MongoDB:',
            error.message
        );

        return null;
    }
}

// ====================================
// LEGACY COMPATIBILITY
// ====================================

/**
 * Existing Nox.js compatibility function.
 *
 * New authentication code should use:
 *
 * getAuthStateFromMongoDB()
 *
 * This function remains exported so existing code does not
 * immediately break.
 */
async function saveSessionToMongoDB(number, credentials) {
    try {
        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const serializedCredentials = serializeAuthValue(credentials);

        await Session.findOneAndUpdate(
            { number: cleanNumber },
            {
                credentials: serializedCredentials,
                updatedAt: new Date()
            },
            {
                upsert: true,
                new: true,
                setDefaultsOnInsert: true
            }
        );

        console.log(`📁 Legacy credentials saved to MongoDB for ${cleanNumber}`);

        return true;

    } catch (error) {
        console.error(
            '❌ Error saving legacy session to MongoDB:',
            error.message
        );

        return false;
    }
}

async function getSessionFromMongoDB(number) {
    try {
        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const session = await Session.findOne({
            number: cleanNumber
        }).lean();

        if (!session) {
            return null;
        }

        if (session.authState?.creds) {
            return deserializeAuthValue(session.authState.creds);
        }

        if (session.credentials) {
            return deserializeAuthValue(session.credentials);
        }

        return null;

    } catch (error) {
        console.error(
            '❌ Error getting legacy session from MongoDB:',
            error.message
        );

        return null;
    }
}

async function deleteSessionFromMongoDB(number) {
    try {
        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        await Session.deleteOne({
            number: cleanNumber
        });

        await ActiveNumber.deleteOne({
            number: cleanNumber
        });

        console.log(`🗑️ Session deleted from MongoDB for ${cleanNumber}`);

        return true;

    } catch (error) {
        console.error(
            '❌ Error deleting session from MongoDB:',
            error.message
        );

        return false;
    }
}

