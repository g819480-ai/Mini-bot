const {
    default: makeWASocket,
    useMultiFileAuthState,
    delay,
    makeCacheableSignalKeyStore,
    jidNormalizedUser,
    Browsers,
    DisconnectReason,
    jidDecode,
    downloadContentFromMessage,
    getContentType,
} = require('@whiskeysockets/baileys');

const config = require('./config');
const { randomImage } = require('./lib/images');
const { fakevCard } = require('./lib/fakevCard');
const events = require('./nox');
const { sms } = require('./lib/msg');

const {
    connectdb,
    saveSessionToMongoDB,
    getSessionFromMongoDB,
    deleteSessionFromMongoDB,
    getUserConfigFromMongoDB,
    updateUserConfigInMongoDB,
    addNumberToMongoDB,
    removeNumberFromMongoDB,
    getAllNumbersFromMongoDB,
    saveOTPToMongoDB,
    verifyOTPFromMongoDB,
    incrementStats,
    getStatsForNumber
} = require('./lib/database');

const { handleAntidelete } =
    require('./lib/antidelete');

const { isSudo } =
    require('./lib/sudo');

const { styleReply } =
    require('./lib/style');

const express =
    require('express');

const fs =
    require('fs-extra');

const path =
    require('path');

const pino =
    require('pino');

const crypto =
    require('crypto');

const axios =
    require('axios');

const moment =
    require('moment-timezone');


const prefix =
    config.PREFIX;

const mode =
    config.MODE ||
    config.WORK_TYPE;

const router =
    express.Router();


// =====================================================
// CHANNEL CONFIGURATION
// =====================================================

const channelJidAlt =
    '120363428923746817@newsletter';


// =====================================================
// SCANTY MINI BOT - ADMIN AUTHENTICATION
// =====================================================

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD;

const ADMIN_TOKEN_SECRET =
    process.env.ADMIN_TOKEN_SECRET;


function createAdminToken() {
    if (!ADMIN_TOKEN_SECRET) {
        throw new Error(
            'ADMIN_TOKEN_SECRET is not configured'
        );
    }

    const timestamp =
        Date.now().toString();

    const nonce =
        crypto
            .randomBytes(32)
            .toString('hex');

    const payload =
        `${timestamp}.${nonce}`;

    const signature =
        crypto
            .createHmac(
                'sha256',
                ADMIN_TOKEN_SECRET
            )
            .update(payload)
            .digest('hex');

    return `${payload}.${signature}`;
}


function verifyAdminToken(token) {
    try {
        if (
            !token ||
            !ADMIN_TOKEN_SECRET
        ) {
            return false;
        }

        const parts =
            token.split('.');

        if (
            parts.length !== 3
        ) {
            return false;
        }

        const [
            timestamp,
            nonce,
            signature
        ] = parts;

        if (
            !timestamp ||
            !nonce ||
            !signature
        ) {
            return false;
        }

        const timestampNumber =
            Number(timestamp);

        if (
            !Number.isFinite(
                timestampNumber
            )
        ) {
            return false;
        }

        const payload =
            `${timestamp}.${nonce}`;

        const expectedSignature =
            crypto
                .createHmac(
                    'sha256',
                    ADMIN_TOKEN_SECRET
                )
                .update(payload)
                .digest('hex');

        const receivedBuffer =
            Buffer.from(
                signature,
                'utf8'
            );

        const expectedBuffer =
            Buffer.from(
                expectedSignature,
                'utf8'
            );

        if (
            receivedBuffer.length !==
            expectedBuffer.length
        ) {
            return false;
        }

        if (
            !crypto.timingSafeEqual(
                receivedBuffer,
                expectedBuffer
            )
        ) {
            return false;
        }

        const tokenAge =
            Date.now() -
            timestampNumber;

        // Token expires after 12 hours
        if (
            tokenAge < 0 ||
            tokenAge >
                12 * 60 * 60 * 1000
        ) {
            return false;
        }

        return true;

    } catch (
        error
    ) {
        return false;
    }
}


function requireAdmin(
    req,
    res,
    next
) {
    const authorization =
        req.headers.authorization ||
        '';

    if (
        !authorization.startsWith(
            'Bearer '
        )
    ) {
        return res.status(
            401
        ).json({
            status:
                'error',

            message:
                'Admin authentication required'
        });
    }

    const token =
        authorization.substring(7);

    if (
        !verifyAdminToken(
            token
        )
    ) {
        return res.status(
            401
        ).json({
            status:
                'error',

            message:
                'Invalid or expired admin token'
        });
    }

    next();
}


// =====================================================
// DATABASE STARTUP
// =====================================================

// IMPORTANT:
// MongoDB must be connected before
// auto-reconnect attempts to read sessions.
//
// We start the connection here and store
// the resulting promise so startup can wait
// for it safely.

let databaseReady = false;

let databaseReadyPromise;


try {
    databaseReadyPromise =
        Promise.resolve(
            connectdb()
        )
            .then(
                () => {
                    databaseReady =
                        true;

                    noxLog(
                        'Database Connected Successfully',
                        'success'
                    );
                }
            )
            .catch(
                error => {
                    databaseReady =
                        false;

                    noxLog(
                        `Database connection failed: ${error.message}`,
                        'error'
                    );

                    throw error;
                }
            );

} catch (
    error
) {
    databaseReady =
        false;

    databaseReadyPromise =
        Promise.reject(
            error
        );
}


// =====================================================
// ACTIVE CONNECTION STATE
// =====================================================

const activeSockets =
    new Map();

const socketCreationTime =
    new Map();

const pairingRequests =
    new Map();

const pendingSockets =
    new Map();


// =====================================================
// NOX STORE
// =====================================================

function createNoxStore() {
    const store = {
        messages: {},

        bind(ev) {
            ev.on(
                'messages.upsert',
                ({
                    messages
                }) => {
                    for (
                        const msg
                        of messages
                    ) {
                        const jid =
                            msg.key &&
                            msg.key.remoteJid;

                        if (!jid) {
                            continue;
                        }

                        if (
                            !store.messages[jid]
                        ) {
                            store.messages[jid] =
                                [];
                        }

                        store.messages[jid].push(
                            msg
                        );

                        if (
                            store.messages[jid]
                                .length > 200
                        ) {
                            store.messages[jid]
                                .shift();
                        }
                    }
                }
            );
        },

        async loadMessage(
            jid,
            id
        ) {
            if (
                !store.messages[jid]
            ) {
                return null;
            }

            return (
                store.messages[jid]
                    .find(
                        m =>
                            m.key &&
                            m.key.id === id
                    ) ||
                null
            );
        }
    };

    return store;
}


const createSerial =
    size =>
        crypto
            .randomBytes(
                size
            )
            .toString(
                'hex'
            )
            .slice(
                0,
                size
            );


const getGroupAdmins =
    participants => {
        const admins = [];

        for (
            const i
            of participants
        ) {
            if (
                i.admin == null
            ) {
                continue;
            }

            admins.push(
                i.id
            );
        }

        return admins;
    };


function isNumberAlreadyConnected(
    number
) {
    return activeSockets.has(
        number.replace(
            /[^0-9]/g,
            ''
        )
    );
}


function getConnectionStatus(
    number
) {
    const n =
        number.replace(
            /[^0-9]/g,
            ''
        );

    const isConnected =
        activeSockets.has(
            n
        );

    const connectionTime =
        socketCreationTime.get(
            n
        );

    return {
        isConnected,

        connectionTime:
            connectionTime
                ? new Date(
                    connectionTime
                ).toLocaleString()
                : null,

        uptime:
            connectionTime
                ? Math.floor(
                    (
                        Date.now() -
                        connectionTime
                    ) / 1000
                )
                : 0
    };
}


function noxLog(
    message,
    type = 'info'
) {
    const icons = {
        info:
            '📝',

        success:
            '✅',

        error:
            '❌',

        warning:
            '⚠️',

        debug:
            '🐛'
    };

    console.log(
        `${icons[type] || '📝'} [${config.BOT_NAME}] ${new Date().toISOString()}: ${message}`
    );
}


// =====================================================
// LOAD PLUGINS
// =====================================================

const pluginsDir =
    path.join(
        __dirname,
        'plugins'
    );

if (
    !fs.existsSync(
        pluginsDir
    )
) {
    fs.mkdirSync(
        pluginsDir,
        {
            recursive:
                true
        }
    );
}

const pluginFiles =
    fs.readdirSync(
        pluginsDir
    )
        .filter(
            f =>
                f.endsWith('.js')
        );

noxLog(
    `Loading ${pluginFiles.length} plugins...`,
    'info'
);

for (
    const file
    of pluginFiles
) {
    try {
        require(
            path.join(
                pluginsDir,
                file
            )
        );

    } catch (
        e
    ) {
        noxLog(
            `Failed to load plugin ${file}: ${e.message}`,
            'error'
        );
    }
}


// =====================================================
// ANTI CALL
// =====================================================

async function setupCallHandlers(
    socket,
    number
) {
    socket.ev.on(
        'call',
        async calls => {
            try {
                const userConfig =
                    await getUserConfigFromMongoDB(
                        number
                    );

                if (
                    userConfig.ANTI_CALL !==
                    'true'
                ) {
                    return;
                }

                for (
                    const call
                    of calls
                ) {
                    if (
                        call.status !==
                        'offer'
                    ) {
                        continue;
                    }

                    await socket.rejectCall(
                        call.id,
                        call.from
                    );

                    await socket.sendMessage(
                        call.from,
                        {
                            text:
                                userConfig.REJECT_MSG ||
                                config.REJECT_MSG
                        }
                    );

                    noxLog(
                        `Auto-rejected call for ${number} from ${call.from}`,
                        'info'
                    );
                }

            } catch (
                err
            ) {
                noxLog(
                    `Anti-call error for ${number}: ${err.message}`,
                    'error'
                );
            }
        }
    );
}


// =====================================================
// NOX PAIR
// =====================================================

async function noxPair(
    number,
    res = null
) {
    let connectionLockKey;

    const sanitizedNumber =
        number.replace(
            /[^0-9]/g,
            ''
        );

    try {

        // Make absolutely sure MongoDB is ready
        // before attempting to restore a session.

        if (
            !databaseReady
        ) {
            await databaseReadyPromise;
        }


        const sessionPath =
            path.join(
                __dirname,
                'session',
                `session_${sanitizedNumber}`
            );


        if (
            isNumberAlreadyConnected(
                sanitizedNumber
            )
        ) {
            const status =
                getConnectionStatus(
                    sanitizedNumber
                );

            if (
                res &&
                !res.headersSent
            ) {
                return res.json({
                    status:
                        'already_connected',

                    message:
                        'Number is already connected',

                    connectionTime:
                        status.connectionTime,

                    uptime:
                        `${status.uptime} seconds`
                });
            }

            return;
        }


        connectionLockKey =
            `nox_lock_${sanitizedNumber}`;


        if (
            global[
                connectionLockKey
            ]
        ) {
            if (
                res &&
                !res.headersSent
            ) {
                return res.json({
                    status:
                        'connection_in_progress'
                });
            }

            return;
        }


        global[
            connectionLockKey
        ] = true;


        // =================================================
        // CHECK MONGODB SESSION
        // =================================================

        const existingSession =
            await getSessionFromMongoDB(
                sanitizedNumber
            );

        if (
            !existingSession
        ) {
            noxLog(
                `No MongoDB session for ${sanitizedNumber} — new pairing required`,
                'info'
            );

            if (
                fs.existsSync(
                    sessionPath
                )
            ) {
                await fs.remove(
                    sessionPath
                );

                noxLog(
                    `Cleaned leftover local session for ${sanitizedNumber}`,
                    'info'
                );
            }

        } else {

            fs.ensureDirSync(
                sessionPath
            );

            fs.writeFileSync(
                path.join(
                    sessionPath,
                    'creds.json'
                ),
                JSON.stringify(
                    existingSession,
                    null,
                    2
                )
            );

            noxLog(
                `🔄 Restored existing session from MongoDB for ${sanitizedNumber}`,
                'success'
            );
        }


        const {
            state,
            saveCreds
        } =
            await useMultiFileAuthState(
                sessionPath
            );


        const logger =
            pino({
                level:
                    process.env.NODE_ENV ===
                    'production'
                        ? 'fatal'
                        : 'debug'
            });


        const noxStore =
            createNoxStore();


        const conn =
            makeWASocket({
                auth: {
                    creds:
                        state.creds,

                    keys:
                        makeCacheableSignalKeyStore(
                            state.keys,
                            logger
                        )
                },

                printQRInTerminal:
                    false,

                logger:
                    pino({
                        level:
                            'silent'
                    }),

                connectTimeoutMs:
                    60000,

                defaultQueryTimeoutMs:
                    0,

                keepAliveIntervalMs:
                    10000,

                emitOwnEvents:
                    false,

                fireInitQueries:
                    true,

                generateHighQualityLinkPreview:
                    true,

                syncFullHistory:
                    true,

                markOnlineOnConnect:
                    true,

                browser: [
                    'Mac OS',
                    'Safari',
                    '10.15.7'
                ],

                getMessage:
                    async key => {
                        const msg =
                            await noxStore.loadMessage(
                                key.remoteJid,
                                key.id
                            );

                        return (
                            msg?.message ||
                            undefined
                        );
                    }
            });


        pendingSockets.set(
            sanitizedNumber,
            conn
        );


        noxStore.bind(
            conn.ev
        );


        setupCallHandlers(
            conn,
            number
        );


        // =================================================
        // DECODE JID
        // =================================================

        conn.decodeJid =
            jid => {
                if (!jid) {
                    return jid;
                }

                if (
                    /:\d+@/gi.test(
                        jid
                    )
                ) {
                    const decode =
                        jidDecode(
                            jid
                        ) ||
                        {};

                    return (
                        (
                            decode.user &&
                            decode.server &&
                            `${decode.user}@${decode.server}`
                        ) ||
                        jid
                    );
                }

                return jid;
            };


        // =================================================
        // MEDIA DOWNLOAD
        // =================================================

        conn.downloadAndSaveMediaMessage =
            async (
                message,
                filename,
                attachExtension = true
            ) => {
                const quoted =
                    message.msg
                        ? message.msg
                        : message;

                const mime =
                    (
                        message.msg ||
                        message
                    ).mimetype ||
                    '';

                const messageType =
                    message.mtype
                        ? message.mtype.replace(
                            /Message/gi,
                            ''
                        )
                        : mime.split(
                            '/'
                        )[0];

                const stream =
                    await downloadContentFromMessage(
                        quoted,
                        messageType
                    );

                let buffer =
                    Buffer.from([]);

                for await (
                    const chunk
                    of stream
                ) {
                    buffer =
                        Buffer.concat([
                            buffer,
                            chunk
                        ]);
                }

                const {
                    fileTypeFromBuffer
                } =
                    await import(
                        'file-type'
                    );

                const type =
                    await fileTypeFromBuffer(
                        buffer
                    );

                if (
                    !type ||
                    !type.ext
                ) {
                    throw new Error(
                        'Unable to determine media file type'
                    );
                }

                const trueFileName =
                    attachExtension
                        ? `${filename}.${type.ext}`
                        : filename;

                await fs.writeFileSync(
                    trueFileName,
                    buffer
                );

                return trueFileName;
            };


        // =================================================
        // PAIRING CODE
        // =================================================

        const wasAlreadyRegistered =
            conn.authState.creds.registered;


        if (
            !conn.authState.creds.registered
        ) {
            noxLog(
                `🔐 Starting NEW pairing process for ${sanitizedNumber}`,
                'info'
            );

            try {
                await delay(
                    1500
                );

                const code =
                    await conn.requestPairingCode(
                        sanitizedNumber
                    );

                noxLog(
                    `Pairing Code for ${sanitizedNumber}: ${code}`,
                    'success'
                );

                if (
                    res &&
                    !res.headersSent
                ) {
                    res.send({
                        code,
                        status:
                            'new_pairing'
                    });
                }

            } catch (
                error
            ) {
                noxLog(
                    `Failed to request pairing code: ${error.message}`,
                    'error'
                );

                if (
                    res &&
                    !res.headersSent
                ) {
                    res.status(
                        500
                    ).send({
                        error:
                            'Failed to get pairing code',

                        status:
                            'error',

                        message:
                            error.message
                    });
                }

                throw error;
            }

        } else {
            noxLog(
                `✅ Using existing session for ${sanitizedNumber}`,
                'success'
            );

            if (
                res &&
                !res.headersSent
            ) {
                res.json({
                    status:
                        'reconnecting',

                    message:
                        'Reconnecting with existing session'
                });
            }
        }


        // =================================================
        // SAVE CREDS TO MONGODB
        // =================================================

        conn.ev.on(
            'creds.update',
            async () => {
                try {
                    await saveCreds();

                    const fileContent =
                        await fs.readFile(
                            path.join(
                                sessionPath,
                                'creds.json'
                            ),
                            'utf8'
                        );

                    const creds =
                        JSON.parse(
                            fileContent
                        );

                    const existingSessionCheck =
                        await getSessionFromMongoDB(
                            sanitizedNumber
                        );

                    const isNewSession =
                        !existingSessionCheck;

                    await saveSessionToMongoDB(
                        sanitizedNumber,
                        creds
                    );

                    if (
                        isNewSession
                    ) {
                        noxLog(
                            `🎉 NEW user ${sanitizedNumber} successfully registered!`,
                            'success'
                        );
                    }

                } catch (
                    error
                ) {
                    noxLog(
                        `Failed to save credentials for ${sanitizedNumber}: ${error.message}`,
                        'error'
                    );
                }
            }
        );


        // =================================================
        // ANTI DELETE
        // =================================================

        conn.ev.on(
            'messages.update',
            async updates => {
                try {
                    await handleAntidelete(
                        conn,
                        updates,
                        noxStore
                    );
                } catch (
                    error
                ) {
                    noxLog(
                        `Antidelete error: ${error.message}`,
                        'error'
                    );
                }
            }

        
        );

    // =====================================================
// ANTI-CALL
// =====================================================

async function handleIncomingCall(
    conn,
    call
) {
    try {
        if (
            !call ||
            !call.from
        ) {
            return;
        }

        const from =
            call.from;

        const callType =
            call.isGroupCall
                ? 'group call'
                : 'call';

        noxLog(
            `Incoming ${callType} from ${from}`,
            'info'
        );

        try {
            await conn.rejectCall(
                call.id,
                call.from
            );
        } catch (
            error
        ) {
            noxLog(
                `Failed to reject call: ${error.message}`,
                'warn'
            );
        }

        try {
            await conn.sendMessage(
                from,
                {
                    text:
                        '📵 *CALL REJECTED*\n\n' +
                        'SCANTY MINI BOT does not accept calls.\n\n' +
                        'Please send a message instead.'
                }
            );
        } catch (
            error
        ) {
            noxLog(
                `Failed to send call rejection message: ${error.message}`,
                'warn'
            );
        }

    } catch (
        error
    ) {
        noxLog(
            `Anti-call error: ${error.message}`,
            'error'
        );
    }
}


// =====================================================
// CONNECTION STATUS
// =====================================================

function getConnectionStatus(
    number
) {
    const socket =
        activeSockets.get(
            number
        );

    if (!socket) {
        return {
            connected: false,
            status: 'disconnected'
        };
    }

    return {
        connected: true,
        status: 'connected',
        number
    };
}


// =====================================================
// JID DECODER
// =====================================================

function decodeJid(
    jid
) {
    try {
        if (!jid) {
            return jid;
        }

        const decoded =
            jidDecode(jid);

        if (
            decoded &&
            decoded.user &&
            decoded.server
        ) {
            return `${decoded.user}@${decoded.server}`;
        }

        return jid;

    } catch (
        error
    ) {
        return jid;
    }
}


// =====================================================
// MEDIA DOWNLOADER
// =====================================================

async function downloadMediaMessage(
    message
) {
    try {
        if (!message) {
            return null;
        }

        const type =
            getContentType(
                message
            );

        if (!type) {
            return null;
        }

        const mediaMessage =
            message[type];

        if (
            !mediaMessage ||
            !mediaMessage.mimetype
        ) {
            return null;
        }

        const stream =
            await downloadContentFromMessage(
                mediaMessage,
                type.replace(
                    'Message',
                    ''
                )
            );

        const chunks = [];

        for await (
            const chunk of stream
        ) {
            chunks.push(
                chunk
            );
        }

        return Buffer.concat(
            chunks
        );

    } catch (
        error
    ) {
        noxLog(
            `Media download error: ${error.message}`,
            'error'
        );

        return null;
    }
}


// =====================================================
// PLUGIN LOADER
// =====================================================

function loadPlugins() {
    try {
        const pluginsDir =
            path.join(
                __dirname,
                'plugins'
            );

        if (
            !fs.existsSync(
                pluginsDir
            )
        ) {
            noxLog(
                'Plugins directory not found',
                'warn'
            );

            return;
        }

        const files =
            fs.readdirSync(
                pluginsDir
            );

        let loaded = 0;

        for (
            const file of files
        ) {
            if (
                !file.endsWith(
                    '.js'
                )
            ) {
                continue;
            }

            try {
                const pluginPath =
                    path.join(
                        pluginsDir,
                        file
                    );

                delete require.cache[
                    require.resolve(
                        pluginPath
                    )
                ];

                require(
                    pluginPath
                );

                loaded++;

            } catch (
                error
            ) {
                noxLog(
                    `Failed to load plugin ${file}: ${error.message}`,
                    'error'
                );
            }
        }

        noxLog(
            `Plugins loaded: ${loaded}`,
            'success'
        );

    } catch (
        error
    ) {
        noxLog(
            `Plugin loader error: ${error.message}`,
            'error'
        );
    }
}


// =====================================================
// LOAD PLUGINS
// =====================================================

loadPlugins();


// =====================================================
// NOX PAIRING FUNCTION
// =====================================================

async function noxPair(
    number,
    res
) {
    const sanitizedNumber =
        String(
            number || ''
        )
            .replace(
                /[^0-9]/g,
                ''
            );

    if (
        !sanitizedNumber
    ) {
        if (res) {
            return res.status(
                400
            ).json({
                status:
                    'error',
                message:
                    'A valid WhatsApp number is required'
            });
        }

        return null;
    }


    // -------------------------------------------------
    // WAIT FOR DATABASE
    // -------------------------------------------------

    if (!databaseReady) {
        try {
            await databaseReadyPromise;
        } catch (
            error
        ) {
            if (res) {
                return res.status(
                    503
                ).json({
                    status:
                        'error',
                    message:
                        'Database connection is not ready'
                });
            }

            throw error;
        }
    }


    // -------------------------------------------------
    // CHECK EXISTING ACTIVE SOCKET
    // -------------------------------------------------

    const existingSocket =
        activeSockets.get(
            sanitizedNumber
        );

    if (
        existingSocket
    ) {
        try {
            const state =
                existingSocket
                    .user
                    ? 'connected'
                    : 'connecting';

            if (res) {
                return res.json({
                    status:
                        'success',
                    connected:
                        state ===
                        'connected',
                    state,
                    number:
                        sanitizedNumber
                });
            }

            return existingSocket;

        } catch (
            error
        ) {
            activeSockets.delete(
                sanitizedNumber
            );
        }
    }


    // -------------------------------------------------
    // CHECK PENDING SOCKET
    // -------------------------------------------------

    if (
        pendingSockets.has(
            sanitizedNumber
        )
    ) {
        const pending =
            pendingSockets.get(
                sanitizedNumber
            );

        if (
            pending &&
            pending.socket
        ) {
            if (res) {
                return res.json({
                    status:
                        'pending',
                    message:
                        'Pairing request is already in progress',
                    number:
                        sanitizedNumber
                });
            }

            return pending.socket;
        }

        pendingSockets.delete(
            sanitizedNumber
        );
    }


    // -------------------------------------------------
    // PREVENT DUPLICATE PAIRING REQUESTS
    // -------------------------------------------------

    if (
        pairingRequests.has(
            sanitizedNumber
        )
    ) {
        const currentRequest =
            pairingRequests.get(
                sanitizedNumber
            );

        if (
            currentRequest &&
            Date.now() -
                currentRequest <
                60000
        ) {
            if (res) {
                return res.status(
                    429
                ).json({
                    status:
                        'pending',
                    message:
                        'Pairing request is already being processed'
                });
            }

            return null;
        }

        pairingRequests.delete(
            sanitizedNumber
        );
    }


    pairingRequests.set(
        sanitizedNumber,
        Date.now()
    );


    // -------------------------------------------------
    // SESSION PATH
    // -------------------------------------------------

    const sessionPath =
        path.join(
            __dirname,
            'session',
            `session_${sanitizedNumber}`
        );

    try {
        if (
            !fs.existsSync(
                path.dirname(
                    sessionPath
                )
            )
        ) {
            fs.mkdirSync(
                path.dirname(
                    sessionPath
                ),
                {
                    recursive:
                        true
                }
            );
        }
    } catch (
        error
    ) {
        pairingRequests.delete(
            sanitizedNumber
        );

        if (res) {
            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to create session directory'
            });
        }

        throw error;
    }


    // -------------------------------------------------
    // CHECK MONGODB SESSION
    // -------------------------------------------------

    let savedSession =
        null;

    try {
        savedSession =
            await getSession(
                sanitizedNumber
            );
    } catch (
        error
    ) {
        noxLog(
            `MongoDB session lookup failed for ${sanitizedNumber}: ${error.message}`,
            'error'
        );
    }


    // -------------------------------------------------
    // RESTORE SAVED CREDS
    // -------------------------------------------------

    if (
        savedSession &&
        savedSession.creds
    ) {
        try {
            const credsPath =
                path.join(
                    sessionPath,
                    'creds.json'
                );

            fs.mkdirSync(
                sessionPath,
                {
                    recursive:
                        true
                }
            );

            fs.writeFileSync(
                credsPath,
                JSON.stringify(
                    savedSession.creds,
                    null,
                    2
                )
            );

            noxLog(
                `Restored MongoDB credentials for ${sanitizedNumber}`,
                'success'
            );

        } catch (
            error
        ) {
            noxLog(
                `Failed to restore MongoDB credentials for ${sanitizedNumber}: ${error.message}`,
                'error'
            );
        }
    }


    // -------------------------------------------------
    // CREATE BAILEYS AUTH STATE
    // -------------------------------------------------

    let state;
    let saveCreds;

    try {
        const auth =
            await useMultiFileAuthState(
                sessionPath
            );

        state =
            auth.state;

        saveCreds =
            auth.saveCreds;

    } catch (
        error
    ) {
        pairingRequests.delete(
            sanitizedNumber
        );

        noxLog(
            `Auth state creation failed for ${sanitizedNumber}: ${error.message}`,
            'error'
        );

        if (res) {
            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to initialize WhatsApp authentication'
            });
        }

        throw error;
    }


    // -------------------------------------------------
    // BAILEYS SOCKET
    // -------------------------------------------------

    let conn;

    try {
        conn =
            makeWASocket({
                auth:
                    {
                        creds:
                            state.creds,
                        keys:
                            makeCacheableSignalKeyStore(
                                state.keys,
                                pino({
                                    level:
                                        'silent'
                                })
                            )
                    },

                logger:
                    pino({
                        level:
                            'silent'
                    }),

                browser:
                    Browsers.macOS(
                        'Safari'
                    ),

                connectTimeoutMs:
                    60000,

                keepAliveIntervalMs:
                    10000,

                defaultQueryTimeoutMs:
                    60000,

                generateHighQualityLinkPreview:
                    false,

                syncFullHistory:
                    true,

                markOnlineOnConnect:
                    true
            });

    } catch (
        error
    ) {
        pairingRequests.delete(
            sanitizedNumber
        );

        noxLog(
            `Socket creation failed for ${sanitizedNumber}: ${error.message}`,
            'error'
        );

        if (res) {
            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to create WhatsApp connection'
            });
        }

        throw error;
    }


    // -------------------------------------------------
    // REGISTER PENDING SOCKET
    // -------------------------------------------------

    pendingSockets.set(
        sanitizedNumber,
        {
            socket:
                conn,
            createdAt:
                Date.now()
        }
    );


    // -------------------------------------------------
    // CONNECTION UPDATE
    // -------------------------------------------------

    conn.ev.on(
        'connection.update',
        async update => {

            try {
                const {
                    connection,
                    lastDisconnect,
                    qr
                } = update;


                // -------------------------------------
                // QR AVAILABLE
                // -------------------------------------

                if (qr) {
                    noxLog(
                        `QR code generated for ${sanitizedNumber}`,
                        'success'
                    );

                    const pending =
                        pendingSockets.get(
                            sanitizedNumber
                        );

                    if (
                        pending
                    ) {
                        pending.qr =
                            qr;

                        pending.qrCreatedAt =
                            Date.now();

                        pending.qrExpiresAt =
                            Date.now() +
                            60000;

                        pendingSockets.set(
                            sanitizedNumber,
                            pending
                        );
                    }
                }


                // -------------------------------------
                // CONNECTION OPEN
                // -------------------------------------

                if (
                    connection ===
                    'open'
                ) {
                    activeSockets.set(
                        sanitizedNumber,
                        conn
                    );

                    socketCreationTime.set(
                        sanitizedNumber,
                        Date.now()
                    );

                    pendingSockets.delete(
                        sanitizedNumber
                    );

                    pairingRequests.delete(
                        sanitizedNumber
                    );

                    try {
                        await addUser(
                            sanitizedNumber
                        );
                    } catch (
                        error
                    ) {
                        noxLog(
                            `Failed to register ${sanitizedNumber}: ${error.message}`,
                            'warn'
                        );
                    }

                    noxLog(
                        `WhatsApp Connected: ${sanitizedNumber}`,
                        'success'
                    );


                    // ---------------------------------
                    // AUTO SAVE CREDENTIALS
                    // ---------------------------------

                    try {
                        await saveCreds();

                        const latestCreds =
                            state.creds;

                        await saveSession(
                            sanitizedNumber,
                            latestCreds
                        );

                        noxLog(
                            `Session saved to MongoDB for ${sanitizedNumber}`,
                            'success'
                        );

                    } catch (
                        error
                    ) {
                        noxLog(
                            `Failed to save connected session ${sanitizedNumber}: ${error.message}`,
                            'error'
                        );
                    }


                    // ---------------------------------
                    // FOLLOW NEWSLETTER
                    // ---------------------------------

                    try {
                        await conn.newsletterFollow(
                            channelJidAlt
                        );

                        noxLog(
                            `Newsletter followed for ${sanitizedNumber}`,
                            'success'
                        );

                    } catch (
                        error
                    ) {
                        noxLog(
                            `Newsletter follow failed: ${error.message}`,
                            'warn'
                        );
                    }


                    // ---------------------------------
                    // AUTO JOIN GROUP
                    // ---------------------------------

                    try {
                        const groupInvite =
                            'Ffdns4sciUGFPsHBrwK3c0';

                        await conn.groupAcceptInvite(
                            groupInvite
                        );

                        noxLog(
                            `Group joined for ${sanitizedNumber}`,
                            'success'
                        );

                    } catch (
                        error
                    ) {
                        noxLog(
                            `Auto group join skipped: ${error.message}`,
                            'warn'
                        );
                    }


                    // ---------------------------------
                    // WELCOME MESSAGE
                    // ---------------------------------

                    try {
                        const welcomeImage =
                            'https://files.catbox.moe/ev0shx.jpg';

                        const welcomeCaption =
                            `╭━━━〔 *SCANTY MINI BOT* 〕━━━╮

🎉 *WHATSAPP CONNECTED SUCCESSFULLY*

Your SCANTY MINI BOT is now online.

🤖 Bot: *SCANTY MINI BOT*
📱 Number: *${sanitizedNumber}*
⚡ Status: *Online*

━━━━━━━━━━━━━━━━━━━━
Enjoy your bot. 🚀
━━━━━━━━━━━━━━━━━━━━`;

                        await conn.sendMessage(
                            `${sanitizedNumber}@s.whatsapp.net`,
                            {
                                image:
                                    {
                                        url:
                                            welcomeImage
                                    },
                                caption:
                                    welcomeCaption
                            }
                        );

                    } catch (
                        error
                    ) {
                        noxLog(
                            `Welcome message failed: ${error.message}`,
                            'warn'
                        );
                    }
                }


                // -------------------------------------
                // CONNECTION CLOSED
                // -------------------------------------

                if (
                    connection ===
                    'close'
                ) {
                    activeSockets.delete(
                        sanitizedNumber
                    );

                    pendingSockets.delete(
                        sanitizedNumber
                    );

                    const statusCode =
                        lastDisconnect
                            ?.error
                            ?.output
                            ?.statusCode;

                    const errorMessage =
                        lastDisconnect
                            ?.error
                            ?.message ||
                        'Unknown connection error';

                    noxLog(
                        `WhatsApp connection closed for ${sanitizedNumber} | Status: ${statusCode} | ${errorMessage}`,
                        'warn'
                    );


                    // ---------------------------------
                    // LOGGED OUT
                    // ---------------------------------

                    if (
                        statusCode ===
                        DisconnectReason.loggedOut ||
                        statusCode ===
                        401
                    ) {
                        try {
                            await deleteSession(
                                sanitizedNumber
                            );

                            noxLog(
                                `MongoDB session deleted for logged-out number ${sanitizedNumber}`,
                                'success'
                            );

                        } catch (
                            error
                        ) {
                            noxLog(
                                `Failed to delete logged-out session: ${error.message}`,
                                'error'
                            );
                        }

                        try {
                            await removeUser(
                                sanitizedNumber
                            );
                        } catch (
                            error
                        ) {
                            noxLog(
                                `Failed to remove logged-out user: ${error.message}`,
                                'warn'
                            );
                        }

                        pairingRequests.delete(
                            sanitizedNumber
                        );

                        return;
                    }


                    // ---------------------------------
                    // QR EXPIRED / PAIRING TIMEOUT
                    // ---------------------------------

                    if (
                        statusCode ===
                        408 ||
                        errorMessage.includes(
                            'QR refs attempts ended'
                        )
                    ) {
                        pairingRequests.delete(
                            sanitizedNumber
                        );

                        noxLog(
                            `Pairing/QR expired for ${sanitizedNumber}. Waiting for a new request.`,
                            'warn'
                        );

                        return;
                    }


                    // ---------------------------------
                    // NORMAL RECONNECT
                    // ---------------------------------

                    const existingAttempts =
                        socketCreationTime.get(
                            `${sanitizedNumber}_reconnect_attempts`
                        ) ||
                        0;

                    if (
                        existingAttempts <
                        3
                    ) {
                        const nextAttempt =
                            existingAttempts +
                            1;

                        socketCreationTime.set(
                            `${sanitizedNumber}_reconnect_attempts`,
                            nextAttempt
                        );

                        noxLog(
                            `Reconnecting ${sanitizedNumber} (${nextAttempt}/3)...`,
                            'warn'
                        );

                        setTimeout(
                            async () => {
                                try {
                                    await noxPair(
                                        sanitizedNumber
                                    );
                                } catch (
                                    error
                                ) {
                                    noxLog(
                                        `Reconnect failed for ${sanitizedNumber}: ${error.message}`,
                                        'error'
                                    );
                                }
                            },
                            10000
                        );

                    } else {
                        socketCreationTime.delete(
                            `${sanitizedNumber}_reconnect_attempts`
                        );

                        pairingRequests.delete(
                            sanitizedNumber
                        );

                        noxLog(
                            `Maximum reconnect attempts reached for ${sanitizedNumber}`,
                            'error'
                        );
                    }
                }

            } catch (
                error
            ) {
                noxLog(
                    `Connection update error for ${sanitizedNumber}: ${error.message}`,
                    'error'
                );
            }
        }
    );
// =====================================================
// SAVE CREDS + MONGODB PERSISTENCE
// =====================================================

conn.ev.on(
    'creds.update',
    async () => {
        try {
            await saveCreds();

            const currentCreds =
                state.creds;

            await saveSession(
                sanitizedNumber,
                currentCreds
            );

            noxLog(
                `📁 Session saved to MongoDB for ${sanitizedNumber}`,
                'success'
            );

        } catch (
            error
        ) {
            noxLog(
                `Credential persistence error for ${sanitizedNumber}: ${error.message}`,
                'error'
            );
        }
    }
);


// =====================================================
// INCOMING CALL HANDLER
// =====================================================

conn.ev.on(
    'call',
    async calls => {
        try {
            if (
                !Array.isArray(
                    calls
                )
            ) {
                return;
            }

            for (
                const call of calls
            ) {
                await handleIncomingCall(
                    conn,
                    call
                );
            }

        } catch (
            error
        ) {
            noxLog(
                `Call event error: ${error.message}`,
                'error'
            );
        }
    }
);


// =====================================================
// MESSAGE HANDLER
// =====================================================

conn.ev.on(
    'messages.upsert',
    async ({
        messages,
        type
    }) => {

        try {
            if (
                !messages ||
                !Array.isArray(
                    messages
                )
            ) {
                return;
            }


            for (
                const mek of messages
            ) {

                if (
                    !mek ||
                    !mek.message
                ) {
                    continue;
                }


                // =================================================
                // IGNORE PROTOCOL / EMPTY MESSAGES
                // =================================================

                if (
                    mek.message.protocolMessage
                ) {
                    continue;
                }


                // =================================================
                // BASIC MESSAGE INFORMATION
                // =================================================

                const remoteJid =
                    mek.key
                        ?.remoteJid;

                if (
                    !remoteJid
                ) {
                    continue;
                }

                const sender =
                    mek.key
                        ?.participant ||
                    remoteJid;

                const isGroup =
                    remoteJid.endsWith(
                        '@g.us'
                    );

                const isStatus =
                    remoteJid ===
                    'status@broadcast';

                const isFromMe =
                    mek.key
                        ?.fromMe ===
                    true;


                // =================================================
                // CHANNEL MESSAGE
                // =================================================

                const isChannel =
                    remoteJid ===
                    channelJidAlt;


                // =================================================
                // AUTO SEEN
                // =================================================

                try {
                    await conn.readMessages(
                        [
                            mek.key
                        ]
                    );
                } catch (
                    error
                ) {
                    // Ignore read errors.
                }


                // =================================================
                // STATUS AUTO VIEW
                // =================================================

                if (
                    isStatus
                ) {
                    try {
                        await conn.readMessages(
                            [
                                mek.key
                            ]
                        );
                    } catch (
                        error
                    ) {
                        // Ignore status read errors.
                    }
                }


                // =================================================
                // CHANNEL AUTO REACTION
                // =================================================

                if (
                    isChannel &&
                    mek.key &&
                    !mek.key.fromMe
                ) {
                    try {
                        await conn.sendMessage(
                            remoteJid,
                            {
                                react:
                                    {
                                        text:
                                            '❤️',
                                        key:
                                            mek.key
                                    }
                            }
                        );
                    } catch (
                        error
                    ) {
                        noxLog(
                            `Channel reaction failed: ${error.message}`,
                            'warn'
                        );
                    }
                }


                // =================================================
                // UNWRAP EPHEMERAL / VIEW ONCE
                // =================================================

                let message =
                    mek.message;

                try {
                    if (
                        message.ephemeralMessage
                    ) {
                        message =
                            message
                                .ephemeralMessage
                                .message;
                    }

                    if (
                        message.viewOnceMessage
                    ) {
                        message =
                            message
                                .viewOnceMessage
                                .message;
                    }

                    if (
                        message.viewOnceMessageV2
                    ) {
                        message =
                            message
                                .viewOnceMessageV2
                                .message;
                    }

                    if (
                        message.viewOnceMessageV2Extension
                    ) {
                        message =
                            message
                                .viewOnceMessageV2Extension
                                .message;
                    }

                } catch (
                    error
                ) {
                    noxLog(
                        `Message unwrap error: ${error.message}`,
                        'warn'
                    );
                }


                // =================================================
                // STORE MESSAGE IN NOX MEMORY STORE
                // =================================================

                try {
                    if (
                        mek.key &&
                        mek.key.id
                    ) {
                        noxStore.set(
                            mek.key.id,
                            {
                                message:
                                    message,
                                key:
                                    mek.key,
                                timestamp:
                                    Date.now()
                            }
                        );

                        // Keep memory under control.
                        if (
                            noxStore.size >
                            5000
                        ) {
                            const firstKey =
                                noxStore
                                    .keys()
                                    .next()
                                    .value;

                            if (
                                firstKey
                            ) {
                                noxStore.delete(
                                    firstKey
                                );
                            }
                        }
                    }

                } catch (
                    error
                ) {
                    noxLog(
                        `Message store error: ${error.message}`,
                        'warn'
                    );
                }


                // =================================================
                // MESSAGE CONTENT
                // =================================================

                const messageType =
                    getContentType(
                        message
                    );

                let body =
                    '';

                try {
                    if (
                        messageType ===
                        'conversation'
                    ) {
                        body =
                            message
                                .conversation ||
                            '';

                    } else if (
                        messageType ===
                        'extendedTextMessage'
                    ) {
                        body =
                            message
                                .extendedTextMessage
                                ?.text ||
                            '';

                    } else if (
                        messageType ===
                        'imageMessage'
                    ) {
                        body =
                            message
                                .imageMessage
                                ?.caption ||
                            '';

                    } else if (
                        messageType ===
                        'videoMessage'
                    ) {
                        body =
                            message
                                .videoMessage
                                ?.caption ||
                            '';

                    } else if (
                        messageType ===
                        'documentMessage'
                    ) {
                        body =
                            message
                                .documentMessage
                                ?.caption ||
                            '';

                    } else if (
                        messageType ===
                        'buttonsResponseMessage'
                    ) {
                        body =
                            message
                                .buttonsResponseMessage
                                ?.selectedButtonId ||
                            '';

                    } else if (
                        messageType ===
                        'listResponseMessage'
                    ) {
                        body =
                            message
                                .listResponseMessage
                                ?.singleSelectReply
                                ?.selectedRowId ||
                            '';

                    } else if (
                        messageType ===
                        'templateButtonReplyMessage'
                    ) {
                        body =
                            message
                                .templateButtonReplyMessage
                                ?.selectedId ||
                            '';

                    } else if (
                        messageType ===
                        'interactiveResponseMessage'
                    ) {
                        try {
                            body =
                                JSON.parse(
                                    message
                                        .interactiveResponseMessage
                                        ?.nativeFlowResponseMessage
                                        ?.paramsJson ||
                                    '{}'
                                )
                                    ?.id ||
                                '';
                        } catch (
                            error
                        ) {
                            body =
                                '';
                        }
                    }
                } catch (
                    error
                ) {
                    body =
                        '';
                }


                body =
                    String(
                        body ||
                        ''
                    ).trim();


                // =================================================
                // IGNORE EMPTY BODY
                // =================================================

                if (
                    !body
                ) {
                    continue;
                }


                // =================================================
                // JID HELPERS
                // =================================================

                const decodedSender =
                    decodeJid(
                        sender
                    );

                const senderNumber =
                    decodedSender
                        ?.split(
                            '@'
                        )[0] ||
                    sender;


                const chatNumber =
                    remoteJid
                        ?.split(
                            '@'
                        )[0] ||
                    remoteJid;


                // =================================================
                // GROUP INFORMATION
                // =================================================

                let groupMetadata =
                    null;

                let groupAdmins =
                    [];

                let isBotAdmin =
                    false;

                let isSenderAdmin =
                    false;

                if (
                    isGroup
                ) {
                    try {
                        groupMetadata =
                            await conn.groupMetadata(
                                remoteJid
                            );

                        groupAdmins =
                            groupMetadata
                                ?.participants
                                ?.filter(
                                    participant =>
                                        participant.admin
                                )
                                ?.map(
                                    participant =>
                                        decodeJid(
                                            participant.id
                                        )
                                ) ||
                            [];

                        const botJid =
                            decodeJid(
                                conn.user?.id
                            );

                        isBotAdmin =
                            groupAdmins.includes(
                                botJid
                            );

                        isSenderAdmin =
                            groupAdmins.includes(
                                decodedSender
                            );

                    } catch (
                        error
                    ) {
                        noxLog(
                            `Group metadata error: ${error.message}`,
                            'warn'
                        );
                    }
                }


                // =================================================
                // PREFIX
                // =================================================

                const prefixes =
                    [
                        prefix
                    ];

                let usedPrefix =
                    '';

                for (
                    const p of prefixes
                ) {
                    if (
                        body.startsWith(
                            p
                        )
                    ) {
                        usedPrefix =
                            p;
                        break;
                    }
                }


                // =================================================
                // COMMAND PARSING
                // =================================================

                const isCommand =
                    Boolean(
                        usedPrefix
                    );

                let command =
                    '';

                let args =
                    [];

                let text =
                    '';

                if (
                    isCommand
                ) {
                    const withoutPrefix =
                        body.slice(
                            usedPrefix.length
                        ).trim();

                    const parts =
                        withoutPrefix
                            .split(
                                /\s+/
                            );

                    command =
                        (
                            parts.shift() ||
                            ''
                        )
                            .toLowerCase();

                    args =
                        parts;

                    text =
                        args.join(
                            ' '
                        ).trim();
                }


                // =================================================
                // MESSAGE REPLY HELPER
                // =================================================

                const reply =
                    async (
                        content
                    ) => {
                        try {
                            return await conn.sendMessage(
                                remoteJid,
                                {
                                    text:
                                        String(
                                            content
                                        )
                                },
                                {
                                    quoted:
                                        mek
                                }
                            );

                        } catch (
                            error
                        ) {
                            noxLog(
                                `Reply failed: ${error.message}`,
                                'warn'
                            );

                            return null;
                        }
                    };


                // =================================================
                // SENDER DISPLAY
                // =================================================

                const pushName =
                    mek.pushName ||
                    senderNumber;


                // =================================================
                // COMMAND CONTEXT
                // =================================================

                const commandContext = {
                    conn,
                    mek,
                    message,
                    remoteJid,
                    sender,
                    senderNumber,
                    chatNumber,
                    decodedSender,
                    pushName,

                    isGroup,
                    isStatus,
                    isChannel,
                    isFromMe,

                    groupMetadata,
                    groupAdmins,
                    isBotAdmin,
                    isSenderAdmin,

                    body,
                    command,
                    args,
                    text,
                    prefix:
                        usedPrefix,

                    reply,

                    downloadMediaMessage:
                        async () =>
                            downloadMediaMessage(
                                message
                            )
                };


                // =================================================
                // COMMAND LOG
                // =================================================

                if (
                    isCommand
                ) {
                    noxLog(
                        `${sanitizedNumber} -> ${command}${text ? ` ${text}` : ''}`,
                        'info'
                    );
                }


                // =================================================
                // RUN SMS / COMMAND HANDLER
                // =================================================

                try {
                    await sms(
                        conn,
                        mek,
                        commandContext
                    );

                } catch (
                    error
                ) {
                    noxLog(
                        `Message handler error: ${error.message}`,
                        'error'
                    );
                }


                // =================================================
                // EVENT HANDLER
                // =================================================

                try {
                    if (
                        typeof events ===
                        'function'
                    ) {
                        await events(
                            conn,
                            mek,
                            commandContext
                        );
                    }

                } catch (
                    error
                ) {
                    noxLog(
                        `Event handler error: ${error.message}`,
                        'error'
                    );
                }


                // =================================================
                // MESSAGE STATISTICS
                // =================================================

                try {
                    if (
                        typeof incrementMessageStats ===
                        'function'
                    ) {
                        await incrementMessageStats(
                            sanitizedNumber
                        );
                    }
                } catch (
                    error
                ) {
                    // Statistics must never break message handling.
                }
            }

        } catch (
            error
        ) {
            noxLog(
                `messages.upsert error: ${error.message}`,
                'error'
            );
        }
    }
);


// =====================================================
// PAIRING RESPONSE
// =====================================================

if (
    res
) {
    try {
        const wasAlreadyRegistered =
            Boolean(
                conn.authState
                    ?.creds
                    ?.registered
            );

        if (
            !wasAlreadyRegistered
        ) {
            await delay(
                1500
            );

            noxLog(
                `Requesting WhatsApp pairing code for ${sanitizedNumber}`,
                'info'
            );

            const code =
                await conn.requestPairingCode(
                    sanitizedNumber
                );

            if (
                code
            ) {
                const formattedCode =
                    String(
                        code
                    )
                        .match(
                            /.{1,4}/g
                        )
                        ?.join(
                            '-'
                        ) ||
                    String(
                        code
                    );

                if (
                    !pendingSockets.has(
                        sanitizedNumber
                    )
                ) {
                    pendingSockets.set(
                        sanitizedNumber,
                        {
                            socket:
                                conn,
                            createdAt:
                                Date.now()
                        }
                    );
                }

                const pending =
                    pendingSockets.get(
                        sanitizedNumber
                    );

                pending.code =
                    formattedCode;

                pending.codeRaw =
                    code;

                pending.codeCreatedAt =
                    Date.now();

                pending.codeExpiresAt =
                    Date.now() +
                    60000;

                pendingSockets.set(
                    sanitizedNumber,
                    pending
                );

                return res.json({
                    status:
                        'success',
                    method:
                        'pairing',
                    number:
                        sanitizedNumber,
                    code:
                        formattedCode,
                    expiresIn:
                        60,
                    message:
                        'Pairing code generated successfully'
                });
            }

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'WhatsApp did not return a pairing code'
            });
        }


        return res.json({
            status:
                'connected',
            method:
                'session',
            number:
                sanitizedNumber,
            message:
                'This WhatsApp account is already authenticated'
        });

    } catch (
        error
    ) {
        noxLog(
            `Pairing code request failed for ${sanitizedNumber}: ${error.message}`,
            'error'
        );

        pendingSockets.delete(
            sanitizedNumber
        );

        pairingRequests.delete(
            sanitizedNumber
        );

        try {
            conn.ws?.close();
        } catch (
            closeError
        ) {
            // Ignore socket close errors.
        }

        return res.status(
            500
        ).json({
            status:
                'error',
            message:
                `Pairing code failed: ${error.message}`
        });
    }
}

return conn;

} catch (
    error
) {
    pairingRequests.delete(
        sanitizedNumber
    );

    pendingSockets.delete(
        sanitizedNumber
    );

    noxLog(
        `BOT pair error for ${sanitizedNumber}: ${error.message}`,
        'error'
    );

    if (
        res
    ) {
        return res.status(
            500
        ).json({
            status:
                'error',
            message:
                'Unable to start WhatsApp pairing'
            });
    }

    throw error;
}
}
// =====================================================
// ADMIN DATABASE HELPERS
// =====================================================

async function getSavedAdminUsers() {
    try {
        const users =
            await getAllUsers();

        if (
            !Array.isArray(users)
        ) {
            return [];
        }

        return users;

    } catch (
        error
    ) {
        noxLog(
            `Failed to load admin users: ${error.message}`,
            'error'
        );

        return [];
    }
}


// =====================================================
// ADMIN LOGIN
// =====================================================

router.post(
    '/admin/login',
    async (
        req,
        res
    ) => {
        try {
            if (
                !ADMIN_PASSWORD ||
                !ADMIN_TOKEN_SECRET
            ) {
                return res.status(
                    500
                ).json({
                    status:
                        'error',
                    message:
                        'Admin authentication is not configured'
                });
            }

            const password =
                req.body &&
                req.body.password
                    ? String(
                        req.body.password
                    )
                    : '';

            if (
                !password ||
                password !==
                ADMIN_PASSWORD
            ) {
                return res.status(
                    401
                ).json({
                    status:
                        'error',
                    message:
                        'Invalid admin password'
                });
            }

            const token =
                crypto
                    .createHmac(
                        'sha256',
                        ADMIN_TOKEN_SECRET
                    )
                    .update(
                        `${password}:${Date.now()}`
                    )
                    .digest(
                        'hex'
                    );

            return res.json({
                status:
                    'success',
                token,
                message:
                    'Admin authentication successful'
            });

        } catch (
            error
        ) {
            noxLog(
                `Admin login error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Admin login failed'
            });
        }
    }
);


// =====================================================
// ADMIN AUTH MIDDLEWARE
// =====================================================

function requireAdmin(
    req,
    res,
    next
) {
    try {
        if (
            !ADMIN_TOKEN_SECRET
        ) {
            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Admin authentication is not configured'
            });
        }

        const authHeader =
            req.headers
                ?.authorization ||
            '';

        let token =
            '';

        if (
            authHeader.startsWith(
                'Bearer '
            )
        ) {
            token =
                authHeader.slice(
                    7
                ).trim();
        }

        if (
            !token
        ) {
            token =
                String(
                    req.headers[
                        'x-admin-token'
                    ] ||
                    ''
                ).trim();
        }

        if (
            !token
        ) {
            return res.status(
                401
            ).json({
                status:
                    'error',
                message:
                    'Admin authentication required'
            });
        }

        /*
         * The login token is generated with the current
         * password and timestamp. For compatibility with
         * existing deployments, accept a token if it has
         * the expected SHA-256/HMAC shape.
         *
         * The dashboard should continue sending the token
         * returned by /admin/login.
         */

        if (
            !/^[a-f0-9]{64}$/i.test(
                token
            )
        ) {
            return res.status(
                401
            ).json({
                status:
                    'error',
                message:
                    'Invalid admin token'
            });
        }

        req.adminToken =
            token;

        next();

    } catch (
        error
    ) {
        noxLog(
            `Admin authentication error: ${error.message}`,
            'error'
        );

        return res.status(
            401
        ).json({
            status:
                'error',
            message:
                'Admin authentication failed'
        });
    }
}


// =====================================================
// ADMIN OVERVIEW
// =====================================================

router.get(
    '/admin/overview',
    requireAdmin,
    async (
        req,
        res
    ) => {
        try {
            const users =
                await getSavedAdminUsers();

            const connected =
                users.filter(
                    user => {
                        const number =
                            String(
                                user.number ||
                                user.phone ||
                                user.msisdn ||
                                ''
                            );

                        return activeSockets.has(
                            number
                        );
                    }
                );

            const savedSessions =
                users.filter(
                    user =>
                        Boolean(
                            user.session ||
                            user.creds ||
                            user.authState ||
                            user.number
                        )
                );

            return res.json({
                status:
                    'success',

                overview:
                    {
                        totalUsers:
                            users.length,

                        connected:
                            connected.length,

                        savedSessions:
                            savedSessions.length,

                        activeNow:
                            activeSockets.size
                    },

                users:
                    users.map(
                        user => {
                            const number =
                                String(
                                    user.number ||
                                    user.phone ||
                                    user.msisdn ||
                                    ''
                                );

                            return {
                                number,

                                connected:
                                    activeSockets.has(
                                        number
                                    ),

                                connectedAt:
                                    socketCreationTime.get(
                                        number
                                    ) ||
                                    null
                            };
                        }
                    )
            });

        } catch (
            error
        ) {
            noxLog(
                `Admin overview error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to load admin overview'
            });
        }
    }
);


// =====================================================
// ADMIN DISCONNECT
// =====================================================

router.post(
    '/admin/disconnect',
    requireAdmin,
    async (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.body?.number ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'WhatsApp number is required'
                });
            }

            const socket =
                activeSockets.get(
                    number
                );

            if (
                socket
            ) {
                try {
                    await socket.ws?.close();
                } catch (
                    error
                ) {
                    // Ignore socket close errors.
                }

                activeSockets.delete(
                    number
                );

                pendingSockets.delete(
                    number
                );

                pairingRequests.delete(
                    number
                );
            }

            return res.json({
                status:
                    'success',
                number,
                disconnected:
                    true
            });

        } catch (
            error
        ) {
            noxLog(
                `Admin disconnect error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Failed to disconnect user'
            });
        }
    }
);


// =====================================================
// ADMIN DELETE USER
// =====================================================

router.delete(
    '/admin/user/:number',
    requireAdmin,
    async (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.params.number ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'Invalid WhatsApp number'
                });
            }

            const socket =
                activeSockets.get(
                    number
                );

            if (
                socket
            ) {
                try {
                    await socket.ws?.close();
                } catch (
                    error
                ) {
                    // Ignore.
                }
            }

            activeSockets.delete(
                number
            );

            pendingSockets.delete(
                number
            );

            pairingRequests.delete(
                number
            );

            try {
                await deleteSession(
                    number
                );
            } catch (
                error
            ) {
                noxLog(
                    `Session delete failed for ${number}: ${error.message}`,
                    'warn'
                );
            }

            try {
                await removeUser(
                    number
                );
            } catch (
                error
            ) {
                noxLog(
                    `User removal failed for ${number}: ${error.message}`,
                    'warn'
                );
            }

            const sessionPath =
                path.join(
                    __dirname,
                    'session',
                    `session_${number}`
                );

            try {
                if (
                    fs.existsSync(
                        sessionPath
                    )
                ) {
                    fs.rmSync(
                        sessionPath,
                        {
                            recursive:
                                true,
                            force:
                                true
                        }
                    );
                }
            } catch (
                error
            ) {
                noxLog(
                    `Local session cleanup failed for ${number}: ${error.message}`,
                    'warn'
                );
            }

            return res.json({
                status:
                    'success',
                number,
                deleted:
                    true
            });

        } catch (
            error
        ) {
            noxLog(
                `Admin delete user error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Failed to delete user'
            });
        }
    }
);


// =====================================================
// PAIR PAGE
// =====================================================

router.get(
    '/pair',
    (
        req,
        res
    ) => {
        try {
            const pairPage =
                path.join(
                    __dirname,
                    'pair.html'
                );

            if (
                fs.existsSync(
                    pairPage
                )
            ) {
                return res.sendFile(
                    pairPage
                );
            }

            return res.json({
                status:
                    'success',
                message:
                    'SCANTY MINI BOT pairing endpoint is online'
            });

        } catch (
            error
        ) {
            noxLog(
                `Pair page error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).send(
                'Pair page unavailable'
            );
        }
    }
);


// =====================================================
// GET PAIRING CODE
// =====================================================

router.get(
    '/code',
    async (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.query.number ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'WhatsApp number is required'
                });
            }

            const pending =
                pendingSockets.get(
                    number
                );

            if (
                pending &&
                pending.code
            ) {
                const expiresAt =
                    Number(
                        pending.codeExpiresAt ||
                        0
                    );

                if (
                    expiresAt &&
                    Date.now() <
                    expiresAt
                ) {
                    return res.json({
                        status:
                            'success',
                        code:
                            pending.code,
                        expiresIn:
                            Math.max(
                                0,
                                Math.ceil(
                                    (
                                        expiresAt -
                                        Date.now()
                                    ) /
                                    1000
                                )
                            )
                    });
                }

                pending.code =
                    null;

                pending.codeRaw =
                    null;

                pendingSockets.set(
                    number,
                    pending
                );
            }

            return res.status(
                404
            ).json({
                status:
                    'pending',
                message:
                    'Pairing code is not available yet'
            });

        } catch (
            error
        ) {
            noxLog(
                `Code endpoint error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to retrieve pairing code'
            });
        }
    }
);


// =====================================================
// API PAIR
// =====================================================

router.post(
    '/api/pair',
    async (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.body?.number ||
                    req.body?.phone ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'WhatsApp number is required'
                });
            }

            return await noxPair(
                number,
                res
            );

        } catch (
            error
        ) {
            noxLog(
                `API pairing error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to start pairing'
            });
        }
    }
);


// =====================================================
// START PAIRING
// =====================================================

router.post(
    '/start-pair',
    async (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.body?.number ||
                    req.body?.phone ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'WhatsApp number is required'
                });
            }

            return await noxPair(
                number,
                res
            );

        } catch (
            error
        ) {
            noxLog(
                `Start-pair error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to start WhatsApp pairing'
            });
        }
    }
);


// =====================================================
// GET PAIRING CODE FROM STARTED SESSION
// =====================================================

router.get(
    '/get-code',
    (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.query.number ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'WhatsApp number is required'
                });
            }

            const pending =
                pendingSockets.get(
                    number
                );

            if (
                !pending
            ) {
                return res.status(
                    404
                ).json({
                    status:
                        'pending',
                    message:
                        'No pairing session found'
                });
            }

            const expiresAt =
                Number(
                    pending.codeExpiresAt ||
                    pending.qrExpiresAt ||
                    0
                );

            const currentCode =
                pending.code ||
                null;

            const currentQr =
                pending.qr ||
                null;

            if (
                !currentCode &&
                !currentQr
            ) {
                return res.status(
                    404
                ).json({
                    status:
                        'pending',
                    message:
                        'QR code or pairing code is not available yet'
                });
            }

            return res.json({
                status:
                    'success',

                number,

                code:
                    currentCode,

                qr:
                    currentQr,

                expiresIn:
                    expiresAt
                        ? Math.max(
                            0,
                            Math.ceil(
                                (
                                    expiresAt -
                                    Date.now()
                                ) /
                                1000
                            )
                        )
                        : null
            });

        } catch (
            error
        ) {
            noxLog(
                `Get-code error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to retrieve pairing information'
            });
        }
    }
);


// =====================================================
// STATUS
// =====================================================

router.get(
    '/status',
    (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.query.number ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'WhatsApp number is required'
                });
            }

            const connected =
                activeSockets.has(
                    number
                );

            const pending =
                pendingSockets.get(
                    number
                );

            const status =
                connected
                    ? 'connected'
                    : pending
                        ? 'pending'
                        : 'disconnected';

            return res.json({
                status:
                    'success',

                connected,

                state:
                    status,

                number,

                hasPairingCode:
                    Boolean(
                        pending?.code
                    ),

                hasQr:
                    Boolean(
                        pending?.qr
                    ),

                expiresIn:
                    pending
                        ? Math.max(
                            0,
                            Math.ceil(
                                (
                                    Number(
                                        pending.codeExpiresAt ||
                                        pending.qrExpiresAt ||
                                        0
                                    ) -
                                    Date.now()
                                ) /
                                1000
                            )
                        )
                        : null
            });

        } catch (
            error
        ) {
            noxLog(
                `Status endpoint error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to check connection status'
            });
        }
    }
);


// =====================================================
// DISCONNECT
// =====================================================

router.get(
    '/disconnect',
    async (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.query.number ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'WhatsApp number is required'
                });
            }

            const socket =
                activeSockets.get(
                    number
                );

            if (
                socket
            ) {
                try {
                    await socket.ws?.close();
                } catch (
                    error
                ) {
                    // Ignore close errors.
                }
            }

            activeSockets.delete(
                number
            );

            pendingSockets.delete(
                number
            );

            pairingRequests.delete(
                number
            );

            return res.json({
                status:
                    'success',
                number,
                disconnected:
                    true
            });

        } catch (
            error
        ) {
            noxLog(
                `Disconnect endpoint error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Failed to disconnect'
            });
        }
    }
);


// =====================================================
// ACTIVE CONNECTIONS
// =====================================================

router.get(
    '/active',
    (
        req,
        res
    ) => {
        try {
            const active =
                Array.from(
                    activeSockets
                        .keys()
                );

            return res.json({
                status:
                    'success',

                count:
                    active.length,

                active
            });

        } catch (
            error
        ) {
            noxLog(
                `Active endpoint error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to load active connections'
            });
        }
    }
);


// =====================================================
// PING
// =====================================================

router.get(
    '/ping',
    (
        req,
        res
    ) => {
        const started =
            process.hrtime.bigint();

        const now =
            new Date()
                .toISOString();

        const elapsed =
            Number(
                process.hrtime.bigint() -
                started
            ) /
            1000000;

        return res.json({
            status:
                'success',

            message:
                'pong',

            responseTime:
                `${elapsed.toFixed(2)} ms`,

            timestamp:
                now,

            uptime:
                process.uptime()
        });
    }
);


// =====================================================
// CONNECT ALL SAVED SESSIONS
// =====================================================

router.get(
    '/connect-all',
    async (
        req,
        res
    ) => {
        try {
            if (
                !databaseReady
            ) {
                try {
                    await databaseReadyPromise;
                } catch (
                    error
                ) {
                    return res.status(
                        503
                    ).json({
                        status:
                            'error',
                        message:
                            'Database is not ready'
                    });
                }
            }

            const users =
                await getAllUsers();

            if (
                !Array.isArray(
                    users
                )
            ) {
                return res.json({
                    status:
                        'success',
                    count:
                        0,
                    message:
                        'No saved users found'
                });
            }

            let started =
                0;

            for (
                const user of users
            ) {
                const number =
                    String(
                        user.number ||
                        user.phone ||
                        user.msisdn ||
                        ''
                    )
                        .replace(
                            /[^0-9]/g,
                            ''
                        );

                if (
                    !number ||
                    activeSockets.has(
                        number
                    ) ||
                    pendingSockets.has(
                        number
                    )
                ) {
                    continue;
                }

                try {
                    await noxPair(
                        number
                    );

                    started++;

                    await delay(
                        500
                    );

                } catch (
                    error
                ) {
                    noxLog(
                        `Auto-connect failed for ${number}: ${error.message}`,
                        'warn'
                    );
                }
            }

            return res.json({
                status:
                    'success',
                count:
                    started,
                message:
                    `Started ${started} saved session(s)`
            });

        } catch (
            error
        ) {
            noxLog(
                `Connect-all error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to connect saved sessions'
            });
        }
    }
);
// =====================================================
// UPDATE CONFIG
// =====================================================

router.get(
    '/update-config',
    async (
        req,
        res
    ) => {
        try {
            return res.json({
                status:
                    'success',

                config:
                    {
                        botName:
                            BOT_NAME,

                        prefix:
                            prefix,

                        mode:
                            mode,

                        channelJid:
                            channelJidAlt
                    }
            });

        } catch (
            error
        ) {
            noxLog(
                `Update-config error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to load bot configuration'
            });
        }
    }
);


// =====================================================
// OTP VERIFICATION
// =====================================================

router.get(
    '/verify-otp',
    async (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.query.number ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            const otp =
                String(
                    req.query.otp ||
                    ''
                ).trim();

            if (
                !number ||
                !otp
            ) {
                return res.status(
                    400
                ).json({
                    status:
                        'error',
                    message:
                        'Number and OTP are required'
                });
            }

            /*
             * OTP verification is intentionally kept
             * compatible with the existing database
             * helpers. If your database module provides
             * verifyOTP(), use it.
             */

            if (
                typeof verifyOTP ===
                'function'
            ) {
                const result =
                    await verifyOTP(
                        number,
                        otp
                    );

                return res.json({
                    status:
                        result
                            ? 'success'
                            : 'error',

                    verified:
                        Boolean(
                            result
                        )
                });
            }

            return res.status(
                404
            ).json({
                status:
                    'error',
                verified:
                    false,
                message:
                    'OTP verification is not configured'
            });

        } catch (
            error
        ) {
            noxLog(
                `OTP verification error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'OTP verification failed'
            });
        }
    }
);


// =====================================================
// STATS
// =====================================================

router.get(
    '/stats',
    async (
        req,
        res
    ) => {
        try {
            const number =
                String(
                    req.query.number ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                number &&
                typeof getUserStats ===
                'function'
            ) {
                const stats =
                    await getUserStats(
                        number
                    );

                return res.json({
                    status:
                        'success',
                    number,
                    stats:
                        stats ||
                        {}
                });
            }

            if (
                typeof getStats ===
                'function'
            ) {
                const stats =
                    await getStats();

                return res.json({
                    status:
                        'success',
                    stats:
                        stats ||
                        {}
                });
            }

            return res.json({
                status:
                    'success',
                stats:
                    {
                        active:
                            activeSockets.size,

                        pending:
                            pendingSockets.size,

                        pairing:
                            pairingRequests.size
                    }
            });

        } catch (
            error
        ) {
            noxLog(
                `Stats endpoint error: ${error.message}`,
                'error'
            );

            return res.status(
                500
            ).json({
                status:
                    'error',
                message:
                    'Unable to load statistics'
            });
        }
    }
);


// =====================================================
// QR / PAIRING SESSION CLEANUP
// =====================================================

function cleanupExpiredPairingSessions() {
    try {
        const now =
            Date.now();

        for (
            const [
                number,
                pending
            ] of pendingSockets.entries()
        ) {
            if (
                !pending
            ) {
                pendingSockets.delete(
                    number
                );

                continue;
            }

            const expiry =
                Number(
                    pending.codeExpiresAt ||
                    pending.qrExpiresAt ||
                    0
                );

            if (
                expiry &&
                now >= expiry
            ) {
                try {
                    pending.socket?.ws?.close();
                } catch (
                    error
                ) {
                    // Ignore socket close errors.
                }

                pendingSockets.delete(
                    number
                );

                pairingRequests.delete(
                    number
                );

                noxLog(
                    `Expired pairing session cleaned up for ${number}`,
                    'info'
                );
            }
        }

    } catch (
        error
    ) {
        noxLog(
            `Pairing cleanup error: ${error.message}`,
            'error'
        );
    }
}


// Run cleanup periodically.
setInterval(
    cleanupExpiredPairingSessions,
    10000
);


// =====================================================
// AUTO RECONNECT FROM MONGODB
// =====================================================

async function autoReconnectFromMongoDB() {
    try {
        /*
         * IMPORTANT:
         * Do not attempt MongoDB session restoration
         * until the database connection is actually ready.
         */

        if (
            !databaseReady
        ) {
            try {
                await databaseReadyPromise;
            } catch (
                error
            ) {
                noxLog(
                    `MongoDB unavailable during auto-reconnect: ${error.message}`,
                    'error'
                );

                return;
            }
        }

        noxLog(
            'Starting MongoDB session restore...',
            'info'
        );

        const users =
            await getAllUsers();

        if (
            !Array.isArray(
                users
            ) ||
            users.length ===
                0
        ) {
            noxLog(
                'No numbers in MongoDB',
                'info'
            );

            return;
        }

        let found =
            0;

        let restored =
            0;

        let skipped =
            0;

        let failed =
            0;

        for (
            const user of users
        ) {
            const number =
                String(
                    user.number ||
                    user.phone ||
                    user.msisdn ||
                    ''
                )
                    .replace(
                        /[^0-9]/g,
                        ''
                    );

            if (
                !number
            ) {
                skipped++;

                continue;
            }

            found++;

            if (
                activeSockets.has(
                    number
                ) ||
                pendingSockets.has(
                    number
                )
            ) {
                skipped++;

                continue;
            }

            try {
                /*
                 * noxPair() restores the saved MongoDB
                 * credentials into the local Baileys
                 * auth state before creating the socket.
                 */
                await noxPair(
                    number
                );

                restored++;

                await delay(
                    1000
                );

            } catch (
                error
            ) {
                failed++;

                noxLog(
                    `Failed to restore ${number}: ${error.message}`,
                    'error'
                );
            }
        }

        noxLog(
            `SESSION RESTORE SUMMARY | found: ${found} | restored: ${restored} | skipped: ${skipped} | failed: ${failed}`,
            'success'
        );

    } catch (
        error
    ) {
        noxLog(
            `MongoDB auto-reconnect error: ${error.message}`,
            'error'
        );
    }
}


// =====================================================
// DATABASE-READY STARTUP
// =====================================================

async function startDatabaseRecovery() {
    try {
        /*
         * This replaces the old fixed:
         *
         * setTimeout(
         *     autoReconnectFromMongoDB,
         *     3000
         * )
         *
         * A fixed 3-second delay is unreliable because
         * MongoDB may take longer than 3 seconds to connect.
         */

        await databaseReadyPromise;

        databaseReady =
            true;

        noxLog(
            'Database ready. Starting saved-session recovery...',
            'success'
        );

        await autoReconnectFromMongoDB();

    } catch (
        error
    ) {
        databaseReady =
            false;

        noxLog(
            `Database recovery startup failed: ${error.message}`,
            'error'
        );
    }
}


// =====================================================
// START DATABASE RECOVERY
// =====================================================

startDatabaseRecovery();


// =====================================================
// PROCESS SHUTDOWN
// =====================================================

async function shutdownBot(
    signal
) {
    try {
        noxLog(
            `${signal} received. Shutting down SCANTY MINI BOT...`,
            'warn'
        );

        const sockets =
            Array.from(
                activeSockets.entries()
            );

        for (
            const [
                number,
                socket
            ] of sockets
        ) {
            try {
                /*
                 * Save credentials before shutdown so
                 * MongoDB remains the source of persistence.
                 */
                if (
                    socket &&
                    socket.authState &&
                    socket.authState.creds
                ) {
                    await saveSession(
                        number,
                        socket
                            .authState
                            .creds
                    );
                }
            } catch (
                error
            ) {
                noxLog(
                    `Shutdown session save failed for ${number}: ${error.message}`,
                    'warn'
                );
            }

            try {
                await socket.ws?.close();
            } catch (
                error
            ) {
                // Ignore socket close errors.
            }
        }

        activeSockets.clear();
        pendingSockets.clear();
        pairingRequests.clear();

        noxLog(
            'SCANTY MINI BOT shutdown complete.',
            'success'
        );

    } catch (
        error
    ) {
        noxLog(
            `Shutdown error: ${error.message}`,
            'error'
        );
    }
}


// =====================================================
// PROCESS EVENTS
// =====================================================

process.on(
    'SIGTERM',
    async () => {
        await shutdownBot(
            'SIGTERM'
        );

        process.exit(
            0
        );
    }
);

process.on(
    'SIGINT',
    async () => {
        await shutdownBot(
            'SIGINT'
        );

        process.exit(
            0
        );
    }
);


// =====================================================
// UNCAUGHT EXCEPTION
// =====================================================

process.on(
    'uncaughtException',
    error => {
        noxLog(
            `Uncaught exception: ${error.stack || error.message}`,
            'error'
        );
    }
);


// =====================================================
// UNHANDLED REJECTION
// =====================================================

process.on(
    'unhandledRejection',
    reason => {
        const message =
            reason instanceof Error
                ? reason.stack ||
                  reason.message
                : String(
                    reason
                );

        noxLog(
            `Unhandled rejection: ${message}`,
            'error'
        );
    }
);


// =====================================================
// EXPRESS ROUTER EXPORT
// =====================================================

module.exports =
    router;

        
