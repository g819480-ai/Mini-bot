const mongoose = require('mongoose');
const config = require('../config');

// ====================================
// DATABASE CONNECTION
// ====================================

let connectionPromise = null;

const connectdb = async () => {
    try {
        mongoose.set('strictQuery', false);

        // Already connected
        if (mongoose.connection.readyState === 1) {
            return true;
        }

        // Already connecting
        if (mongoose.connection.readyState === 2 && connectionPromise) {
            return await connectionPromise;
        }

        connectionPromise = mongoose.connect(config.MONGODB_URI, {
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
        })
        .then(() => {
            console.log('✅ Database Connected Successfully');
            return true;
        })
        .catch((error) => {
            console.error(
                '❌ Database Connection Failed:',
                error.message
            );

            connectionPromise = null;
            return false;
        });

        return await connectionPromise;

    } catch (error) {
        console.error(
            '❌ Database Connection Failed:',
            error.message
        );

        connectionPromise = null;
        return false;
    }
};

// Make every database operation wait for MongoDB.
// This prevents:
// "Operation activenumbers.find() buffering timed out"
async function ensureDatabaseConnection() {
    if (mongoose.connection.readyState === 1) {
        return true;
    }

    if (mongoose.connection.readyState === 2 && connectionPromise) {
        return await connectionPromise;
    }

    return await connectdb();
}

// ====================================
// BAILEYS BUFFER SERIALIZATION
// ====================================

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
// SESSION SCHEMA
// ====================================

const sessionSchema = new mongoose.Schema({
    number: {
        type: String,
        required: true,
        unique: true,
        index: true
    },

    authState: {
        type: mongoose.Schema.Types.Mixed,
        required: true
    },

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

// ====================================
// USER CONFIG SCHEMA
// ====================================

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

// ====================================
// OTP SCHEMA
// ====================================

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

async function saveAuthStateToMongoDB(number, authState) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return false;
        }

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

        console.log(
            `📁 Complete Baileys auth state saved to MongoDB for ${cleanNumber}`
        );

        return true;

    } catch (error) {
        console.error(
            '❌ Error saving Baileys auth state to MongoDB:',
            error.message
        );

        return false;
    }
}

async function getAuthStateFromMongoDB(number) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return null;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const session = await Session.findOne({
            number: cleanNumber
        }).lean();

        if (!session) {
            return null;
        }

        if (session.authState) {
            return deserializeAuthValue(session.authState);
        }

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

async function saveSessionToMongoDB(number, credentials) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return false;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const serializedCredentials =
            serializeAuthValue(credentials);

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

        console.log(
            `📁 Legacy credentials saved to MongoDB for ${cleanNumber}`
        );

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
        if (!(await ensureDatabaseConnection())) {
            return null;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const session = await Session.findOne({
            number: cleanNumber
        }).lean();

        if (!session) {
            return null;
        }

        if (session.authState?.creds) {
            return deserializeAuthValue(
                session.authState.creds
            );
        }

        if (session.credentials) {
            return deserializeAuthValue(
                session.credentials
            );
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
        if (!(await ensureDatabaseConnection())) {
            return false;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        await Session.deleteOne({
            number: cleanNumber
        });

        await ActiveNumber.deleteOne({
            number: cleanNumber
        });

        console.log(
            `🗑️ Session deleted from MongoDB for ${cleanNumber}`
        );

        return true;

    } catch (error) {
        console.error(
            '❌ Error deleting session from MongoDB:',
            error.message
        );

        return false;
    }
}

// ====================================
// USER CONFIG
// ====================================

async function getUserConfigFromMongoDB(number) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return null;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        let userConfig = await UserConfig.findOne({
            number: cleanNumber
        }).lean();

        if (!userConfig) {
            userConfig = await UserConfig.create({
                number: cleanNumber
            });

            return userConfig.config;
        }

        return userConfig.config;

    } catch (error) {
        console.error(
            '❌ Error getting user config:',
            error.message
        );

        return null;
    }
}

async function updateUserConfigInMongoDB(number, updates) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return false;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        await UserConfig.findOneAndUpdate(
            { number: cleanNumber },
            {
                $set: {
                    config: updates,
                    updatedAt: new Date()
                }
            },
            {
                upsert: true,
                new: true,
                setDefaultsOnInsert: true
            }
        );

        return true;

    } catch (error) {
        console.error(
            '❌ Error updating user config:',
            error.message
        );

        return false;
    }
}

// ====================================
// OTP
// ====================================

async function saveOTPToMongoDB(number, otp, configData) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return false;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        await OTP.findOneAndUpdate(
            { number: cleanNumber },
            {
                otp: String(otp),
                config: configData,
                expiresAt: new Date(Date.now() + 5 * 60000)
            },
            {
                upsert: true,
                new: true
            }
        );

        return true;

    } catch (error) {
        console.error(
            '❌ Error saving OTP:',
            error.message
        );

        return false;
    }
}

async function verifyOTPFromMongoDB(number, otp) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return null;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const record = await OTP.findOne({
            number: cleanNumber,
            otp: String(otp)
        }).lean();

        if (!record) {
            return null;
        }

        if (
            record.expiresAt &&
            new Date(record.expiresAt).getTime() < Date.now()
        ) {
            await OTP.deleteOne({
                _id: record._id
            });

            return null;
        }

        await OTP.deleteOne({
            _id: record._id
        });

        return record.config;

    } catch (error) {
        console.error(
            '❌ Error verifying OTP:',
            error.message
        );

        return null;
    }
}

// ====================================
// ACTIVE NUMBERS
// ====================================

async function addNumberToMongoDB(
    number,
    connectionInfo = {}
) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return false;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        await ActiveNumber.findOneAndUpdate(
            { number: cleanNumber },
            {
                number: cleanNumber,
                lastConnected: new Date(),
                isActive: true,
                connectionInfo: {
                    ...connectionInfo,
                    timestamp: new Date()
                }
            },
            {
                upsert: true,
                new: true,
                setDefaultsOnInsert: true
            }
        );

        return true;

    } catch (error) {
        console.error(
            '❌ Error adding active number:',
            error.message
        );

        return false;
    }
}

async function removeNumberFromMongoDB(number) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return false;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        await ActiveNumber.deleteOne({
            number: cleanNumber
        });

        return true;

    } catch (error) {
        console.error(
            '❌ Error removing active number:',
            error.message
        );

        return false;
    }
}

async function getAllNumbersFromMongoDB() {
    try {
        if (!(await ensureDatabaseConnection())) {
            return [];
        }

        const numbers = await ActiveNumber.find({
            isActive: true
        }).lean();

        return numbers.map(item => item.number);

    } catch (error) {
        console.error(
            '❌ Error getting active numbers:',
            error.message
        );

        return [];
    }
}

// ====================================
// STATS
// ====================================

async function incrementStats(number, field) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return false;
        }

        const allowedFields = [
            'commandsUsed',
            'messagesReceived',
            'messagesSent',
            'groupsInteracted'
        ];

        if (!allowedFields.includes(field)) {
            return false;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const today = new Date();

        const date = [
            today.getUTCFullYear(),
            String(today.getUTCMonth() + 1).padStart(2, '0'),
            String(today.getUTCDate()).padStart(2, '0')
        ].join('-');

        await Stats.findOneAndUpdate(
            {
                number: cleanNumber,
                date
            },
            {
                $inc: {
                    [field]: 1
                }
            },
            {
                upsert: true,
                new: true,
                setDefaultsOnInsert: true
            }
        );

        return true;

    } catch (error) {
        console.error(
            '❌ Error incrementing stats:',
            error.message
        );

        return false;
    }
}

async function getStatsForNumber(number) {
    try {
        if (!(await ensureDatabaseConnection())) {
            return null;
        }

        const cleanNumber = String(number).replace(/[^0-9]/g, '');

        const today = new Date();

        const date = [
            today.getUTCFullYear(),
            String(today.getUTCMonth() + 1).padStart(2, '0'),
            String(today.getUTCDate()).padStart(2, '0')
        ].join('-');

        return await Stats.findOne({
            number: cleanNumber,
            date
        }).lean();

    } catch (error) {
        console.error(
            '❌ Error getting stats:',
            error.message
        );

        return null;
    }
}

// ====================================
// COMPATIBILITY ALIASES
// ====================================

async function getUserConfig(number) {
    return await getUserConfigFromMongoDB(number);
}

async function updateUserConfig(number, updates) {
    return await updateUserConfigInMongoDB(
        number,
        updates
    );
}

// ====================================
// EXPORTS
// ====================================

module.exports = {
    connectdb,

    Session,
    UserConfig,
    OTP,
    ActiveNumber,
    Stats,

    saveAuthStateToMongoDB,
    getAuthStateFromMongoDB,

    saveSessionToMongoDB,
    getSessionFromMongoDB,
    deleteSessionFromMongoDB,

    getUserConfigFromMongoDB,
    updateUserConfigInMongoDB,

    saveOTPToMongoDB,
    verifyOTPFromMongoDB,

    addNumberToMongoDB,
    removeNumberFromMongoDB,
    getAllNumbersFromMongoDB,

    incrementStats,
    getStatsForNumber,

    getUserConfig,
    updateUserConfig
};
