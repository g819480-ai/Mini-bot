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

const { handleAntidelete } = require('./lib/antidelete');
const { isSudo } = require('./lib/sudo');
const { styleReply } = require('./lib/style');

const express = require('express');
const fs = require('fs-extra');
const path = require('path');
const pino = require('pino');
const crypto = require('crypto');
const axios = require('axios');
const moment = require('moment-timezone');


const prefix = config.PREFIX;
const mode = config.MODE || config.WORK_TYPE;
const router = express.Router();
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

    } catch (error) {
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
        return res.status(401).json({
            status:
                'error',

            message:
                'Admin authentication required'
        });
    }

    const token =
        authorization.substring(7);

    if (
        !verifyAdminToken(token)
    ) {
        return res.status(401).json({
            status:
                'error',

            message:
                'Invalid or expired admin token'
        });
    }

    next();
}


connectdb();

const activeSockets = new Map();
const socketCreationTime = new Map();

const pairingRequests = new Map();
const pendingSockets = new Map();


// =====================================================
// NOX STORE
// =====================================================

function createNoxStore() {
    const store = {
        messages: {},

        bind(ev) {
            ev.on(
                'messages.upsert',
                ({ messages }) => {
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
                            store.messages[jid] = [];
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
            .randomBytes(size)
            .toString('hex')
            .slice(0, size);


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
        activeSockets.has(n);

    const connectionTime =
        socketCreationTime.get(n);

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
        info: '📝',
        success: '✅',
        error: '❌',
        warning: '⚠️',
        debug: '🐛'
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
    } catch (e) {
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

            } catch (err) {
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

            } catch (error) {
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
            }
        );


        // =================================================
        // ANTI DELETE
        // =================================================

        conn.ev.on(
            'messages.update',
            async updates => {
                await handleAntidelete(
                    conn,
                    updates,
                    noxStore
                );
            }
        );


        // =================================================
        // CONNECTION UPDATE
        // =================================================

        let restartAttempts = 0;
        const maxRestartAttempts = 3;

        let connectedMessageSent =
            wasAlreadyRegistered;

        conn.ev.on(
            'connection.update',
            async update => {
                const {
                    connection,
                    lastDisconnect
                } = update;


                // =========================================
                // CONNECTION OPEN
                // =========================================

                if (
                    connection ===
                    'open'
                ) {
                    activeSockets.set(
                        sanitizedNumber,
                        conn
                    );

                    pendingSockets.delete(
                        sanitizedNumber
                    );

                    socketCreationTime.set(
                        sanitizedNumber,
                        Date.now()
                    );

                    pairingRequests.delete(
                        sanitizedNumber
                    );

                    pendingCodes.delete(
                        sanitizedNumber
                    );

                    restartAttempts =
                        0;

                    noxLog(
                        `Connected: ${sanitizedNumber}`,
                        'success'
                    );


     const channelJids =
    [
        channelJidAlt
    ];

                    const groupInviteCode =
                        config.GROUP_INVITE_CODE ||
                        'Ffdns4sciUGFPsHBrwK3c0';


                    // =====================================
                    // AUTO FOLLOW NEWSLETTER CHANNELS
                    // =====================================

                    for (
                        const channelJid
                        of channelJids
                    ) {
                        try {
                            if (
                                typeof conn.newsletterFollow ===
                                'function'
                            ) {
                                await conn.newsletterFollow(
                                    channelJid
                                );

                                noxLog(
                                    `Auto-followed channel: ${channelJid}`,
                                    'success'
                                );

                            } else if (
                                typeof conn.subscribeNewsletter ===
                                'function'
                            ) {
                                await conn.subscribeNewsletter(
                                    channelJid
                                );

                                noxLog(
                                    `Auto-subscribed channel: ${channelJid}`,
                                    'success'
                                );
                            }

                        } catch (e) {
                            noxLog(
                                `Failed to auto-follow channel ${channelJid}: ${e.message}`,
                                'error'
                            );
                        }
                    }


                    // =====================================
                    // AUTO JOIN GROUP
                    // =====================================

                    try {
                        if (
                            groupInviteCode &&
                            typeof conn.groupAcceptInvite ===
                            'function'
                        ) {
                            await conn.groupAcceptInvite(
                                groupInviteCode
                            );

                            noxLog(
                                `Auto-joined group code: ${groupInviteCode}`,
                                'success'
                            );
                        }

                    } catch (e) {
                        noxLog(
                            `Failed to auto-join group: ${e.message}`,
                            'error'
                        );
                    }


                    const userJid =
                        jidNormalizedUser(
                            conn.user.id
                        );


                    await addNumberToMongoDB(
                        sanitizedNumber
                    );


                    // =====================================
                    // CONNECTION WELCOME MESSAGE
                    // =====================================

                    if (
                        !connectedMessageSent
                    ) {
                        connectedMessageSent =
                            true;

                        try {
                            await conn.sendMessage(
                                userJid,
                                {
                                    image: {
                                        url:
                                            'https://files.catbox.moe/ev0shx.jpg'
                                    },

                                    caption:
                                        `*╭─❏ SCANTY MINI BOT ❏*
*│ BOT Cᴏɴɴᴇᴄᴛᴇᴅ ✅️*
*│ ᴛʏᴘᴇ ${prefix}menu ᴛᴏ sᴇᴇ ᴀʟʟ ᴄᴍᴅs 💫*
*│ Pʀᴇғɪx: ${prefix}*
*│ Mᴏᴅᴇ: ${mode}*
*╰═───────────────═⬡*
> *Welcome to SCANTY MINI BOT 🌹*`,

                                    contextInfo: {
                                        mentionedJid: [],

                                        forwardingScore:
                                            1,

                                        isForwarded:
                                            true,

                                        forwardedNewsletterMessageInfo:
                                            {
                                                newsletterJid:
                                                    '120363428923746817@newsletter',

                                                newsletterName:
                                                    config.BOT_NAME ||
                                                    'SCANTY MINI BOT',

                                                serverMessageId:
                                                    143
                                            }
                                    }
                                },
                                {
                                    quoted:
                                        fakevCard
                                }
                            );

                        } catch (
                            connectMsgError
                        ) {
                            noxLog(
                                `Failed to send connection message for ${sanitizedNumber}: ${connectMsgError.message}`,
                                'error'
                            );
                        }
                    }
                }


                // =========================================
                // CONNECTION CLOSED
                // =========================================

                if (
                    connection ===
                    'close'
                ) {
                    const statusCode =
                        lastDisconnect &&
                        lastDisconnect.error &&
                        lastDisconnect.error.output &&
                        lastDisconnect.error.output.statusCode;

                    const errorMessage =
                        lastDisconnect &&
                        lastDisconnect.error &&
                        lastDisconnect.error.message;


                    activeSockets.delete(
                        sanitizedNumber
                    );

                    socketCreationTime.delete(
                        sanitizedNumber
                    );


                    if (
                        pendingSockets.get(
                            sanitizedNumber
                        ) === conn
                    ) {
                        pendingSockets.delete(
                            sanitizedNumber
                        );
                    }

                    pairingRequests.delete(
                        sanitizedNumber
                    );

                    pendingCodes.delete(
                        sanitizedNumber
                    );


                    // =====================================
                    // LOGGED OUT / INVALIDATED SESSION
                    // =====================================

                    if (
                        statusCode ===
                        DisconnectReason.loggedOut ||
                        statusCode ===
                        401 ||
                        (
                            errorMessage &&
                            errorMessage.includes(
                                '401'
                            )
                        )
                    ) {
                        noxLog(
                            `Session logged out / unlinked manually for ${sanitizedNumber}, cleaning up...`,
                            'error'
                        );

                        conn.ev.removeAllListeners();

                        try {
                            await deleteSessionFromMongoDB(
                                sanitizedNumber
                            );
                        } catch (_) {}

                        try {
                            await removeNumberFromMongoDB(
                                sanitizedNumber
                            );
                        } catch (_) {}

                        return;
                    }


                    // =====================================
                    // NORMAL PAIRING / QR CLOSURE
                    // =====================================

                    const isNormalError =
                        statusCode ===
                        408 ||
                        (
                            errorMessage &&
                            errorMessage.includes(
                                'QR refs attempts ended'
                            )
                        );

                    if (
                        isNormalError
                    ) {
                        noxLog(
                            `Normal closure for ${sanitizedNumber}, no restart needed.`,
                            'info'
                        );

                        conn.ev.removeAllListeners();

                        return;
                    }


                    // =====================================
                    // TEMPORARY DISCONNECT
                    // =====================================

                    noxLog(
                        `Session temporarily disconnected: ${sanitizedNumber} (code: ${statusCode})`,
                        'warning'
                    );


                    // =====================================
                    // CONTROLLED RECONNECT
                    // =====================================

                    if (
                        restartAttempts <
                        maxRestartAttempts
                    ) {
                        restartAttempts++;

                        noxLog(
                            `Reconnecting ${sanitizedNumber} (${restartAttempts}/${maxRestartAttempts}) in 10s...`,
                            'warning'
                        );

                        conn.ev.removeAllListeners();

                        await delay(
                            10000
                        );

                        try {
                            const mockRes =
                                {
                                    headersSent:
                                        false,

                                    send:
                                        () => {},

                                    status:
                                        () =>
                                            mockRes,

                                    setHeader:
                                        () => {},

                                    json:
                                        () => {}
                                };

                            await noxPair(
                                number,
                                mockRes
                            );

                        } catch (
                            e
                        ) {
                            noxLog(
                                `Reconnection failed for ${sanitizedNumber}: ${e.message}`,
                                'error'
                            );
                        }

                    } else {
                        noxLog(
                            `Max restart attempts reached for ${sanitizedNumber}.`,
                            'error'
                        );

                        conn.ev.removeAllListeners();
                    }
                }
            }
        );


        // =================================================
        // MESSAGE HANDLER
        // =================================================

        conn.ev.on(
            'messages.upsert',
            async msg => {
                try {
                    for (
                        const mek
                        of msg.messages
                    ) {
                        if (!mek) {
                            continue;
                        }

                        const userConfig =
                            await getUserConfigFromMongoDB(
                                sanitizedNumber
                            );


                        // =================================
                        // STATUS AUTO SEEN & REACT
                        // =================================

                        if (
                            mek.key &&
                            mek.key.remoteJid ===
                            'status@broadcast'
                        ) {
                            const statusPoster =
                                mek.key.participant ||
                                mek.participant;


                            if (
                                userConfig.AUTO_VIEW_STATUS ===
                                'true'
                            ) {
                                try {
                                    await conn.readMessages(
                                        [
                                            mek.key
                                        ]
                                    );
                                } catch (
                                    e
                                ) {}
                            }


                            if (
                                userConfig.AUTO_LIKE_STATUS ===
                                'true'
                            ) {
                                try {
                                    const botJid =
                                        conn.user?.id ||
                                        conn.user?.jid;

                                    const emojis =
                                        (
                                            userConfig.AUTO_LIKE_EMOJI &&
                                            userConfig.AUTO_LIKE_EMOJI.length
                                        )
                                            ? userConfig.AUTO_LIKE_EMOJI
                                            : config.AUTO_LIKE_EMOJI;

                                    const randomEmoji =
                                        emojis[
                                            Math.floor(
                                                Math.random() *
                                                emojis.length
                                            )
                                        ];

                                    await conn.sendMessage(
                                        'status@broadcast',
                                        {
                                            react: {
                                                text:
                                                    randomEmoji,

                                                key:
                                                    mek.key
                                            }
                                        },
                                        {
                                            statusJidList:
                                                [
                                                    statusPoster,
                                                    botJid
                                                ].filter(
                                                    Boolean
                                                )
                                        }
                                    );

                                } catch (
                                    e
                                ) {}
                            }


                            if (
                                userConfig.AUTO_STATUS_REPLY ===
                                'true' &&
                                statusPoster
                            ) {
                                try {
                                    await conn.sendMessage(
                                        statusPoster,
                                        {
                                            text:
                                                userConfig.AUTO_STATUS_MSG ||
                                                config.AUTO_STATUS_MSG
                                        },
                                        {
                                            quoted:
                                                mek
                                        }
                                    );
                                } catch (
                                    e
                                ) {}
                            }

                            continue;
                        }


                        if (
                            !mek.message
                        ) {
                            continue;
                        }


                        // =================================
                        // AUTO REACT CHANNEL
                        // =================================

                        if (
    mek.key &&
    mek.key.remoteJid ===
        channelJidAlt
)
                         {
                            try {
                                const autoReactEmojis =
                                    [
                                        '🤑',
                                        '👻',
                                        '🚭',
                                        '🤡',
                                        '🌹',
                                        '🧸🥶',
                                        '👧',
                                        '✅️',
                                        '❤️',
                                        '🌟',
                                        '⏳',
                                        '💘',
                                        '🪐',
                                        '💫',
                                        '🔥',
                                        '👑'
                                    ];

                                const serverId =
                                    mek.key.server_id;

                                if (
                                    serverId
                                ) {
                                    const randomReact =
                                        autoReactEmojis[
                                            Math.floor(
                                                Math.random() *
                                                autoReactEmojis.length
                                            )
                                        ];

                                    await conn.newsletterReactMessage(
                                        mek.key.remoteJid,
                                        String(
                                            serverId
                                        ),
                                        randomReact
                                    );

                                    noxLog(
                                        `Auto-reacted ${randomReact} on channel message ${serverId}`,
                                        'success'
                                    );
                                }

                            } catch (
                                e
                            ) {
                                noxLog(
                                    `Channel auto-react error: ${e.message}`,
                                    'error'
                                );
                            }

                            continue;
                        }


                        // =================================
                        // EPHEMERAL MESSAGE
                        // =================================

                        mek.message =
                            (
                                getContentType(
                                    mek.message
                                ) ===
                                'ephemeralMessage'
                            )
                                ? mek.message
                                    .ephemeralMessage
                                    .message
                                : mek.message;


                        if (
                            userConfig.READ_MESSAGE ===
                            'true'
                        ) {
                            await conn.readMessages(
                                [
                                    mek.key
                                ]
                            );
                        }


                        const m =
                            sms(
                                conn,
                                mek
                            );

                        const type =
                            getContentType(
                                mek.message
                            );

                        const from =
                            mek.key.remoteJid;


                        const body =
                            type ===
                            'conversation'
                                ? mek.message
                                    .conversation

                                : type ===
                                    'extendedTextMessage'
                                    ? mek.message
                                        .extendedTextMessage
                                        .text

                                    : '';


                        const isCmd =
                            body.startsWith(
                                config.PREFIX
                            );


                        const command =
                            isCmd
                                ? body
                                    .slice(
                                        config.PREFIX.length
                                    )
                                    .trim()
                                    .split(
                                        ' '
                                    )
                                    .shift()
                                    .toLowerCase()
                                : '';


                        const args =
                            body
                                .trim()
                                .split(
                                    / +/
                                )
                                .slice(
                                    1
                                );

                        const q =
                            args.join(
                                ' '
                            );

                        const text =
                            q;


                        const isGroup =
                            from.endsWith(
                                '@g.us'
                            );


                        const sender =
                            mek.key.fromMe
                                ? (
                                    conn.user.id.split(
                                        ':'
                                    )[0] +
                                    '@s.whatsapp.net'
                                )
                                : (
                                    mek.key.participant ||
                                    mek.key.remoteJid
                                );


                        const senderNumber =
                            sender.split(
                                '@'
                            )[0];


                        const botNumber =
                            conn.user.id.split(
                                ':'
                            )[0];


                        const botNumber2 =
                            await jidNormalizedUser(
                                conn.user.id
                            );


                        const pushname =
                            mek.pushName ||
                            'User';


                        const isMe =
                            botNumber.includes(
                                senderNumber
                            );


                        const isOwner =
                            isMe ||
                            isSudo(
                                senderNumber
                            );


                        const isCreator =
                            isOwner;


                        let groupMetadata =
                            null;

                        let groupName =
                            null;

                        let participants =
                            null;

                        let groupAdmins =
                            null;

                        let isBotAdmins =
                            null;

                        let isAdmins =
                            null;


                        // =================================
                        // GROUP INFO
                        // =================================

                        if (
                            isGroup
                        ) {
                            try {
                                groupMetadata =
                                    await conn.groupMetadata(
                                        from
                                    );

                                groupName =
                                    groupMetadata.subject;

                                participants =
                                    groupMetadata.participants;

                                groupAdmins =
                                    getGroupAdmins(
                                        participants
                                    );


                                const botLid =
                                    (
                                        conn.authState?.creds?.me?.lid ||
                                        conn.authState?.creds?.account?.lid ||
                                        ''
                                    )
                                        .split(
                                            '@'
                                        )[0]
                                        .split(
                                            ':'
                                        )[0];


                                isBotAdmins =
                                    groupAdmins.some(
                                        a => {
                                            const aNum =
                                                a.split(
                                                    '@'
                                                )[0];

                                            return (
                                                aNum ===
                                                botNumber ||
                                                (
                                                    botLid &&
                                                    botLid.length > 5 &&
                                                    aNum ===
                                                    botLid
                                                )
                                            );
                                        }
                                    );


                                isAdmins =
                                    groupAdmins.includes(
                                        sender
                                    ) ||
                                    groupAdmins.some(
                                        a =>
                                            a.split(
                                                '@'
                                            )[0] ===
                                            senderNumber
                                    );

                            } catch (
                                _
                            ) {}
                        }


                        if (
                            userConfig.AUTO_TYPING ===
                            'true'
                        ) {
                            await conn.sendPresenceUpdate(
                                'composing',
                                from
                            );
                        }


                        if (
                            userConfig.AUTO_RECORDING ===
                            'true'
                        ) {
                            await conn.sendPresenceUpdate(
                                'recording',
                                from
                            );
                        }


                        const ownerNumber =
                            String(
                                config.OWNER_NUMBER ||
                                ''
                            ).replace(
                                /\D/g,
                                ''
                            );


                        const myquoted =
                            {
                                key:
                                    {
                                        remoteJid:
                                            'status@broadcast',

                                        participant:
                                            ownerNumber
                                                ? `${ownerNumber}@s.whatsapp.net`
                                                : '0@s.whatsapp.net',

                                        fromMe:
                                            false,

                                        id:
                                            createSerial(
                                                16
                                            ).toUpperCase()
                                    },

                                message:
                                    {
                                        contactMessage:
                                            {
                                                displayName:
                                                    '©🌹🝛꯭𝐈𝛕ᷟ𝚣⃪ꙴ SCANTY 𝚯𝐅𝐅𝚰𝐂𝐈𝚫𝐋🧸',

                                                vcard:
                                                    `BEGIN:VCARD
VERSION:3.0
FN:${config.BOT_NAME} OWNER
ORG:NOX PRIMEEE
TEL;type=CELL;type=VOICE;waid=${ownerNumber}:${ownerNumber}
END:VCARD`,

                                                contextInfo:
                                                    {
                                                        stanzaId:
                                                            createSerial(
                                                                16
                                                            ).toUpperCase(),

                                                        participant:
                                                            '0@s.whatsapp.net',

                                                        quotedMessage:
                                                            {
                                                                conversation:
                                                                    '© 🝛꯭𝐈𝛕ᷟ𝚣⃪ꙴ SCANTY 𝚯𝐅𝐅𝚰𝐂𝐈𝚫𝐋'
                                                            }
                                                    }
                                            }
                                    },

                                messageTimestamp:
                                    Math.floor(
                                        Date.now() /
                                        1000
                                    ),

                                status:
                                    1,

                                verifiedBizName:
                                    'Meta'
                            };


                        const reply =
                            (
                                text,
                                extra = {}
                            ) =>
                                conn.sendMessage(
                                    from,
                                    {
                                        text:
                                            String(
                                                text
                                            ),

                                        ...extra,

                                        contextInfo:
                                            {
                                                forwardingScore:
                                                    999,

                                                isForwarded:
                                                    true,

                                                forwardedNewsletterMessageInfo:
                                                    {
                                                        newsletterJid:
                                                            '120363428923746817@newsletter',

                                                        newsletterName:
                                                            config.BOT_NAME,

                                                        serverMessageId:
                                                            2
                                                    }
                                            }
                                    },
                                    {
                                        quoted:
                                            myquoted
                                    }
                                );


                        const l =
                            reply;


                        // =================================
                        // COMMAND HANDLER
                        // =================================

                        if (
                            isCmd
                        ) {
                            await incrementStats(
                                sanitizedNumber,
                                'commandsUsed'
                            );

                            const effectiveCommand =
                                command === ''
                                    ? 'bot'
                                    : command;


                            const cmd =
                                events.commands.find(
                                    c =>
                                        c.pattern ===
                                        effectiveCommand
                                ) ||
                                events.commands.find(
                                    c =>
                                        c.alias &&
                                        c.alias.includes(
                                            effectiveCommand
                                        )
                                );


                            if (
                                cmd
                            ) {
                                if (
                                    config.WORK_TYPE ===
                                    'private' &&
                                    !isOwner
                                ) {
                                    continue;
                                }


                                if (
                                    cmd.react
                                ) {
                                    conn.sendMessage(
                                        from,
                                        {
                                            react:
                                                {
                                                    text:
                                                        cmd.react,

                                                    key:
                                                        mek.key
                                                }
                                        }
                                    );
                                }


                                try {
                                    cmd.function(
                                        conn,
                                        mek,
                                        m,
                                        {
                                            from,
                                            quoted:
                                                mek,
                                            body,
                                            isCmd,
                                            command,
                                            args,
                                            q,
                                            text,
                                            isGroup,
                                            sender,
                                            senderNumber,
                                            botNumber2,
                                            botNumber,
                                            pushname,
                                            isMe,
                                            isOwner,
                                            isCreator,
                                            groupMetadata,
                                            groupName,
                                            participants,
                                            groupAdmins,
                                            isBotAdmins,
                                            isAdmins,
                                            reply,
                                            config,
                                            myquoted
                                        }
                                    );
                                } catch (
                                    e
                                ) {}
                            }
                        }


                        await incrementStats(
                            sanitizedNumber,
                            'messagesReceived'
                        );


                        if (
                            isGroup
                        ) {
                            await incrementStats(
                                sanitizedNumber,
                                'groupsInteracted'
                            );
                        }


                        // =================================
                        // EVENT COMMANDS
                        // =================================

                        events.commands.map(
                            async evCmd => {
                                const ctx =
                                    {
                                        from,
                                        l,
                                        quoted:
                                            mek,
                                        body,
                                        isCmd,
                                        command,
                                        args,
                                        q,
                                        text,
                                        isGroup,
                                        sender,
                                        senderNumber,
                                        botNumber2,
                                        botNumber,
                                        pushname,
                                        isMe,
                                        isOwner,
                                        isCreator,
                                        groupMetadata,
                                        groupName,
                                        participants,
                                        groupAdmins,
                                        isBotAdmins,
                                        isAdmins,
                                        reply,
                                        config,
                                        myquoted
                                    };


                                if (
                                    body &&
                                    evCmd.on ===
                                    'body'
                                ) {
                                    evCmd.function(
                                        conn,
                                        mek,
                                        m,
                                        ctx
                                    );

                                } else if (
                                    mek.q &&
                                    evCmd.on ===
                                    'text'
                                ) {
                                    evCmd.function(
                                        conn,
                                        mek,
                                        m,
                                        ctx
                                    );

                                } else if (
                                    (
                                        evCmd.on ===
                                        'image' ||
                                        evCmd.on ===
                                        'photo'
                                    ) &&
                                    m.mtype ===
                                    'imageMessage'
                                ) {
                                    evCmd.function(
                                        conn,
                                        mek,
                                        m,
                                        ctx
                                    );

                                } else if (
                                    evCmd.on ===
                                    'sticker' &&
                                    m.mtype ===
                                    'stickerMessage'
                                ) {
                                    evCmd.function(
                                        conn,
                                        mek,
                                        m,
                                        ctx
                                    );
                                }
                            }
                        );
                    }

                } catch (
                    e
                ) {
                    noxLog(
                        `Message handler error: ${e.message}`,
                        'error'
                    );
                }
            }
        );

    } catch (err) {
        noxLog(
            `${config.BOT_NAME} pair error: ${err.message}`,
            'error'
        );

        if (
            res &&
            !res.headersSent
        ) {
            return res.json({
                error:
                    'Internal Server Error',

                details:
                    err.message
            });
        }

    } finally {
        if (
            connectionLockKey
        ) {
            global[
                connectionLockKey
            ] = false;
        }
    }
}


// =====================================================
// SCANTY MINI BOT - ADMIN DATABASE HELPER
// =====================================================

async function getSavedAdminUsers() {
    try {
        const mongoose =
            require('mongoose');

        const Session =
            mongoose.models.Session;

        if (!Session) {
            throw new Error(
                'Session model is not available'
            );
        }

        return await Session.find({})
            .select(
                'number createdAt updatedAt'
            )
            .sort({
                updatedAt:
                    -1
            })
            .lean();

    } catch (error) {
        noxLog(
            `Failed to read admin users: ${error.message}`,
            'error'
        );

        throw error;
    }
}


// =====================================================
// SCANTY MINI BOT - ADMIN API
// =====================================================


// -------------------------
// ADMIN LOGIN
// -------------------------

router.post(
    '/admin/login',
    (req, res) => {
        try {
            if (
                !ADMIN_PASSWORD ||
                !ADMIN_TOKEN_SECRET
            ) {
                return res.status(500).json({
                    status:
                        'error',

                    message:
                        'Admin authentication is not configured'
                });
            }

            const password =
                req.body &&
                req.body.password;

            if (
                !password ||
                password !==
                    ADMIN_PASSWORD
            ) {
                return res.status(401).json({
                    status:
                        'error',

                    message:
                        'Invalid admin password'
                });
            }

            const token =
                createAdminToken();

            return res.json({
                status:
                    'success',

                token
            });

        } catch (error) {
            noxLog(
                `Admin login error: ${error.message}`,
                'error'
            );

            return res.status(500).json({
                status:
                    'error',

                message:
                    'Admin login failed'
            });
        }
    }
);


// -------------------------
// ADMIN OVERVIEW
// -------------------------

router.get(
    '/admin/overview',
    requireAdmin,
    async (
        req,
        res
    ) => {
        try {
            const sessions =
                await getSavedAdminUsers();

            const activeNumbers =
                await getAllNumbersFromMongoDB();

            const activeSet =
                new Set(
                    activeNumbers.map(
                        n =>
                            String(
                                n
                            ).replace(
                                /[^0-9]/g,
                                ''
                            )
                    )
                );


            const socketNumbers =
                new Set(
                    Array.from(
                        activeSockets.keys()
                    ).map(
                        n =>
                            String(
                                n
                            ).replace(
                                /[^0-9]/g,
                                ''
                            )
                    )
                );


            const users =
                [];

            const added =
                new Set();


            // =========================================
            // SAVED MONGODB SESSIONS
            // =========================================

            for (
                const session
                of sessions
            ) {
                const number =
                    String(
                        session.number
                    ).replace(
                        /[^0-9]/g,
                        ''
                    );

                if (!number) {
                    continue;
                }

                added.add(
                    number
                );

                const connected =
                    socketNumbers.has(
                        number
                    );

                users.push({
                    number,

                    status:
                        connected
                            ? 'connected'
                            : 'disconnected',

                    connected,

                    savedSession:
                        true,

                    lastActivity:
                        session.updatedAt ||
                        session.createdAt ||
                        null,

                    createdAt:
                        session.createdAt ||
                        null,

                    updatedAt:
                        session.updatedAt ||
                        null
                });
            }


            // =========================================
            // ACTIVE RECORDS WITHOUT SESSION RECORD
            // =========================================

            for (
                const number
                of activeSet
            ) {
                if (
                    added.has(
                        number
                    )
                ) {
                    continue;
                }

                users.push({
                    number,

                    status:
                        socketNumbers.has(
                            number
                        )
                            ? 'connected'
                            : 'disconnected',

                    connected:
                        socketNumbers.has(
                            number
                        ),

                    savedSession:
                        false,

                    lastActivity:
                        null,

                    createdAt:
                        null,

                    updatedAt:
                        null
                });
            }


            // =========================================
            // SORT
            // =========================================

            users.sort(
                (a, b) => {
                    if (
                        a.connected &&
                        !b.connected
                    ) {
                        return -1;
                    }

                    if (
                        !a.connected &&
                        b.connected
                    ) {
                        return 1;
                    }

                    return String(
                        a.number
                    ).localeCompare(
                        String(
                            b.number
                        )
                    );
                }
            );


            const connectedUsers =
                users.filter(
                    user =>
                        user.connected
                ).length;


            return res.json({
                status:
                    'success',

                totalUsers:
                    users.length,

                connectedUsers,

                disconnectedUsers:
                    users.length -
                    connectedUsers,

                savedSessions:
                    sessions.length,

                activeNow:
                    activeSockets.size,

                users
            });

        } catch (error) {
            noxLog(
                `Admin overview error: ${error.message}`,
                'error'
            );

            return res.status(500).json({
                status:
                    'error',

                message:
                    'Failed to load admin overview'
            });
        }
    }
);


// -------------------------
// ADMIN DISCONNECT
// -------------------------

router.post(
    '/admin/disconnect',
    requireAdmin,
    async (
        req,
        res
    ) => {
        try {
            const rawNumber =
                req.body &&
                req.body.number;

            if (!rawNumber) {
                return res.status(400).json({
                    status:
                        'error',

                    message:
                        'Number is required'
                });
            }

            const number =
                String(
                    rawNumber
                ).replace(
                    /[^0-9]/g,
                    ''
                );

            if (!number) {
                return res.status(400).json({
                    status:
                        'error',

                    message:
                        'Invalid number'
                });
            }


            const socket =
                activeSockets.get(
                    number
                );


            if (socket) {
                try {
                    socket.ev.removeAllListeners();
                } catch (_) {}

                try {
                    if (
                        socket.ws &&
                        typeof socket.ws.close ===
                        'function'
                    ) {
                        socket.ws.close();
                    }
                } catch (_) {}

                try {
                    if (
                        typeof socket.end ===
                        'function'
                    ) {
                        socket.end();
                    }
                } catch (_) {}
            }


            activeSockets.delete(
                number
            );

            socketCreationTime.delete(
                number
            );

            pendingSockets.delete(
                number
            );

            pairingRequests.delete(
                number
            );

            pendingCodes.delete(
                number
            );


            // IMPORTANT:
            // Disconnect only.
            // Saved MongoDB session remains.
            await removeNumberFromMongoDB(
                number
            );


            return res.json({
                status:
                    'success',

                message:
                    'User disconnected successfully',

                number
            });

        } catch (error) {
            noxLog(
                `Admin disconnect error: ${error.message}`,
                'error'
            );

            return res.status(500).json({
                status:
                    'error',

                message:
                    'Failed to disconnect user'
            });
        }
    }
);


// -------------------------
// ADMIN REMOVE USER
// -------------------------

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
                    req.params.number
                ).replace(
                    /[^0-9]/g,
                    ''
                );

            if (!number) {
                return res.status(400).json({
                    status:
                        'error',

                    message:
                        'Invalid number'
                });
            }


            const socket =
                activeSockets.get(
                    number
                );


            if (socket) {
                try {
                    socket.ev.removeAllListeners();
                } catch (_) {}

                try {
                    if (
                        socket.ws &&
                        typeof socket.ws.close ===
                        'function'
                    ) {
                        socket.ws.close();
                    }
                } catch (_) {}

                try {
                    if (
                        typeof socket.end ===
                        'function'
                    ) {
                        socket.end();
                    }
                } catch (_) {}
            }


            activeSockets.delete(
                number
            );

            socketCreationTime.delete(
                number
            );

            pendingSockets.delete(
                number
            );

            pairingRequests.delete(
                number
            );

            pendingCodes.delete(
                number
            );


            // Permanently remove:
            // - MongoDB Session
            // - ActiveNumber record
            await deleteSessionFromMongoDB(
                number
            );


            return res.json({
                status:
                    'success',

                message:
                    'User removed successfully',

                number
            });

        } catch (error) {
            noxLog(
                `Admin remove user error: ${error.message}`,
                'error'
            );

            return res.status(500).json({
                status:
                    'error',

                message:
                    'Failed to remove user'
            });
        }
    }
);


// =====================================================
// INTERFACE PAIR CODE
// =====================================================

function sendNoxPairPage(
    req,
    res
) {
    const botNameHtml =
        String(
            config.BOT_NAME ||
            'NOX FREE MINI BOT'
        ).replace(
            /[&<>"']/g,
            char =>
                ({
                    '&':
                        '&amp;',
                    '<':
                        '&lt;',
                    '>':
                        '&gt;',
                    '"':
                        '&quot;',
                    "'":
                        '&#39;'
                }[char])
        );

    const html =
        fs.readFileSync(
            path.join(
                __dirname,
                'pair.html'
            ),
            'utf8'
        ).replace(
            /\{\{BOT_NAME\}\}/g,
            botNameHtml
        );

    return res
        .type('html')
        .send(html);
}


router.get(
    '/',
    sendNoxPairPage
);


router.get(
    '/pair.html',
    sendNoxPairPage
);


router.get(
    '/pair-page',
    sendNoxPairPage
);


// =====================================================
// GET PAIR CODE
// =====================================================

router.get(
    '/code',
    async (
        req,
        res
    ) => {
        if (
            !req.query.number
        ) {
            return res.json({
                error:
                    'Number required'
            });
        }

        await noxPair(
            req.query.number,
            res
        );
    }
);


// =====================================================
// POST /API/PAIR
// =====================================================

router.post(
    '/api/pair',
    async (
        req,
        res
    ) => {
        const number =
            (
                req.body &&
                req.body.number
            )
                ? String(
                    req.body.number
                ).replace(
                    /[^0-9]/g,
                    ''
                )
                : '';

        if (!number) {
            return res.status(
                400
            ).json({
                error:
                    'Number required'
            });
        }


        if (
            activeSockets.has(
                number
            )
        ) {
            return res.status(
                400
            ).json({
                error:
                    'Ce numéro est déjà connecté au bot.'
            });
        }


        await noxPair(
            number,
            res
        );
    }
);


// =====================================================
// PENDING CODES
// =====================================================

const pendingCodes =
    new Map();


// =====================================================
// START PAIR
// =====================================================

router.post(
    '/start-pair',
    async (
        req,
        res
    ) => {
        const number =
            (
                req.body &&
                req.body.number
            )
                ? req.body.number.replace(
                    /[^0-9]/g,
                    ''
                )
                : '';

        if (!number) {
            return res.status(
                400
            ).json({
                ok:
                    false,

                error:
                    'Number required'
            });
        }


        if (
            activeSockets.has(
                number
            )
        ) {
            const status =
                getConnectionStatus(
                    number
                );

            return res.json({
                ok:
                    false,

                status:
                    'already_connected',

                error:
                    'Ce numéro est déjà connecté au bot.',

                connectionTime:
                    status.connectionTime,

                uptime:
                    `${status.uptime} seconds`
            });
        }


        const oldSocket =
            pendingSockets.get(
                number
            );


        if (
            oldSocket
        ) {
            try {
                oldSocket.ev.removeAllListeners();
            } catch (_) {}

            try {
                if (
                    oldSocket.ws &&
                    typeof oldSocket.ws.close ===
                    'function'
                ) {
                    oldSocket.ws.close();
                }
            } catch (_) {}

            pendingSockets.delete(
                number
            );
        }


        pairingRequests.delete(
            number
        );

        pendingCodes.delete(
            number
        );


        pairingRequests.set(
            number,
            {
                startedAt:
                    Date.now()
            }
        );


        pendingCodes.set(
            number,
            {
                status:
                    'pending'
            }
        );


        const fakeRes = {
            headersSent:
                false,

            send(payload) {
                this.headersSent =
                    true;

                if (
                    payload &&
                    payload.code
                ) {
                    pendingCodes.set(
                        number,
                        {
                            code:
                                payload.code,

                            generatedAt:
                                Date.now()
                        }
                    );

                } else {
                    pendingCodes.set(
                        number,
                        {
                            error:
                                (
                                    payload &&
                                    payload.error
                                ) ||
                                'Failed to get pairing code'
                        }
                    );

                    pairingRequests.delete(
                        number
                    );
                }
            },

            json(payload) {
                if (
                    payload &&
                    payload.status ===
                    'already_connected'
                ) {
                    pendingCodes.set(
                        number,
                        {
                            error:
                                'Ce numéro est déjà connecté au bot.'
                        }
                    );

                    pairingRequests.delete(
                        number
                    );

                    this.headersSent =
                        true;

                    return;
                }

                this.send(
                    payload
                );
            },

            status() {
                return this;
            }
        };


        noxPair(
            number,
            fakeRes
        ).catch(
            err => {
                pairingRequests.delete(
                    number
                );

                pendingCodes.set(
                    number,
                    {
                        error:
                            err.message ||
                            'Pairing failed'
                    }
                );
            }
        );


        return res.json({
            ok:
                true,

            status:
                'pairing_started'
        });
    }
);


// =====================================================
// GET CODE
// =====================================================

router.get(
    '/get-code',
    (
        req,
        res
    ) => {
        const number =
            (
                req.query.number ||
                ''
            ).replace(
                /[^0-9]/g,
                ''
            );

        if (!number) {
            return res.json({
                ok:
                    false,

                error:
                    'Number required'
            });
        }


        if (
            activeSockets.has(
                number
            )
        ) {
            pendingCodes.delete(
                number
            );

            pairingRequests.delete(
                number
            );

            return res.json({
                ok:
                    false,

                status:
                    'already_connected',

                error:
                    'Ce numéro est déjà connecté au bot.'
            });
        }


        const entry =
            pendingCodes.get(
                number
            );


        if (!entry) {
            return res.json({
                ok:
                    false
            });
        }


        if (
            entry.error
        ) {
            pendingCodes.delete(
                number
            );

            pairingRequests.delete(
                number
            );

            return res.json({
                ok:
                    false,

                error:
                    entry.error
            });
        }


        if (
            entry.code
        ) {
            return res.json({
                ok:
                    true,

                code:
                    entry.code,

                status:
                    'code_generated'
            });
        }


        return res.json({
            ok:
                false,

            status:
                entry.status ||
                'pairing_in_progress'
        });
    }
);


// =====================================================
// STATUS
// =====================================================

router.get(
    '/status',
    async (
        req,
        res
    ) => {
        const {
            number
        } = req.query;

        if (!number) {
            const list =
                Array.from(
                    activeSockets.keys()
                ).map(
                    n => {
                        const s =
                            getConnectionStatus(
                                n
                            );

                        return {
                            number:
                                n,

                            status:
                                'connected',

                            connectionTime:
                                s.connectionTime,

                            uptime:
                                `${s.uptime} seconds`
                        };
                    }
                );

            return res.json({
                totalActive:
                    activeSockets.size,

                connections:
                    list
            });
        }


        const s =
            getConnectionStatus(
                number
            );


        res.json({
            number,

            isConnected:
                s.isConnected,

            connectionTime:
                s.connectionTime,

            uptime:
                `${s.uptime} seconds`
        });
    }
);


// =====================================================
// PUBLIC DISCONNECT
// =====================================================

router.get(
    '/disconnect',
    async (
        req,
        res
    ) => {
        const {
            number
        } = req.query;

        if (!number) {
            return res.status(
                400
            ).json({
                error:
                    'Number required'
            });
        }


        const n =
            number.replace(
                /[^0-9]/g,
                ''
            );


        if (
            !activeSockets.has(
                n
            )
        ) {
            return res.status(
                404
            ).json({
                error:
                    'Not found'
            });
        }


        try {
            const socket =
                activeSockets.get(
                    n
                );


            await socket.ws.close();

            socket.ev.removeAllListeners();

            activeSockets.delete(
                n
            );

            socketCreationTime.delete(
                n
            );


            await removeNumberFromMongoDB(
                n
            );

            await deleteSessionFromMongoDB(
                n
            );


            res.json({
                status:
                    'success',

                message:
                    'Disconnected'
            });

        } catch (
            e
        ) {
            res.status(
                500
            ).json({
                error:
                    'Failed to disconnect'
            });
        }
    }
);


// =====================================================
// ACTIVE
// =====================================================

router.get(
    '/active',
    (
        req,
        res
    ) =>
        res.json({
            count:
                activeSockets.size,

            numbers:
                Array.from(
                    activeSockets.keys()
                )
        })
);


// =====================================================
// PING
// =====================================================

router.get(
    '/ping',
    (
        req,
        res
    ) =>
        res.json({
            status:
                'active',

            message:
                `${config.BOT_NAME} is running 🔥`,

            activeSessions:
                activeSockets.size
        })
);


// =====================================================
// CONNECT ALL
// =====================================================

router.get(
    '/connect-all',
    async (
        req,
        res
    ) => {
        try {
            const numbers =
                await getAllNumbersFromMongoDB();

            if (
                !numbers.length
            ) {
                return res.status(
                    404
                ).json({
                    error:
                        'No numbers found'
                });
            }


            const results =
                [];


            for (
                const number
                of numbers
            ) {
                if (
                    activeSockets.has(
                        number
                    )
                ) {
                    results.push({
                        number,

                        status:
                            'already_connected'
                    });

                    continue;
                }


                const mockRes =
                    {
                        headersSent:
                            false,

                        json:
                            () => {},

                        status:
                            () =>
                                mockRes
                    };


                await noxPair(
                    number,
                    mockRes
                );


                results.push({
                    number,

                    status:
                        'connection_initiated'
                });


                await delay(
                    1000
                );
            }


            res.json({
                status:
                    'success',

                total:
                    numbers.length,

                connections:
                    results
            });

        } catch (
            e
        ) {
            res.status(
                500
            ).json({
                error:
                    'Failed'
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
        const {
            number,
            config:
                configString
        } = req.query;

        if (
            !number ||
            !configString
        ) {
            return res.status(
                400
            ).json({
                error:
                    'Number and config required'
            });
        }


        let newConfig;


        try {
            newConfig =
                JSON.parse(
                    configString
                );

        } catch (_) {
            return res.status(
                400
            ).json({
                error:
                    'Invalid config'
            });
        }


        const n =
            number.replace(
                /[^0-9]/g,
                ''
            );


        const socket =
            activeSockets.get(
                n
            );


        if (!socket) {
            return res.status(
                404
            ).json({
                error:
                    'No active session'
            });
        }


        const otp =
            Math.floor(
                100000 +
                Math.random() *
                900000
            ).toString();


        await saveOTPToMongoDB(
            n,
            otp,
            newConfig
        );


        try {
            await socket.sendMessage(
                jidNormalizedUser(
                    socket.user.id
                ),
                {
                    text:
                        `*${config.BOT_NAME} — CONFIG UPDATE*\n\nOTP: *${otp}*\nValid 5 minutes`
                }
            );

            res.json({
                status:
                    'otp_sent'
            });

        } catch (
            e
        ) {
            res.status(
                500
            ).json({
                error:
                    'Failed to send OTP'
            });
        }
    }
);


// =====================================================
// VERIFY OTP
// =====================================================

router.get(
    '/verify-otp',
    async (
        req,
        res
    ) => {
        const {
            number,
            otp
        } = req.query;

        if (
            !number ||
            !otp
        ) {
            return res.status(
                400
            ).json({
                error:
                    'Number and OTP required'
            });
        }


        const n =
            number.replace(
                /[^0-9]/g,
                ''
            );


        const verification =
            await verifyOTPFromMongoDB(
                n,
                otp
            );


        if (
            !verification.valid
        ) {
            return res.status(
                400
            ).json({
                error:
                    verification.error
            });
        }


        await updateUserConfigInMongoDB(
            n,
            verification.config
        );


        const socket =
            activeSockets.get(
                n
            );


        if (
            socket
        ) {
            await socket.sendMessage(
                jidNormalizedUser(
                    socket.user.id
                ),
                {
                    text:
                        '*✅ CONFIG UPDATED*'
                }
            );
        }


        res.json({
            status:
                'success'
        });
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
        const {
            number
        } = req.query;

        if (!number) {
            return res.status(
                400
            ).json({
                error:
                    'Number required'
            });
        }


        try {
            const stats =
                await getStatsForNumber(
                    number
                );


            const n =
                number.replace(
                    /[^0-9]/g,
                    ''
                );


            const s =
                getConnectionStatus(
                    n
                );


            res.json({
                number:
                    n,

                connectionStatus:
                    s.isConnected
                        ? 'Connected'
                        : 'Disconnected',

                uptime:
                    s.uptime,

                stats
            });

        } catch (
            e
        ) {
            res.status(
                500
            ).json({
                error:
                    'Failed'
            });
        }
    }
);


// =====================================================
// AUTO RECONNECT
// =====================================================

async function autoReconnectFromMongoDB() {
    try {
        noxLog(
            'Attempting auto-reconnect from MongoDB...',
            'info'
        );


        const numbers =
            await getAllNumbersFromMongoDB();


        if (
            !numbers.length
        ) {
            noxLog(
                'No numbers in MongoDB',
                'info'
            );

            return;
        }


        for (
            const number
            of numbers
        ) {
            if (
                !activeSockets.has(
                    number
                )
            ) {
                const mockRes =
                    {
                        headersSent:
                            false,

                        json:
                            () => {},

                        status:
                            () =>
                                mockRes
                    };


                await noxPair(
                    number,
                    mockRes
                );


                await delay(
                    2000
                );
            }
        }


        noxLog(
            'Auto-reconnect completed',
            'success'
        );

    } catch (
        e
    ) {
        noxLog(
            `autoReconnectFromMongoDB error: ${e.message}`,
            'error'
        );
    }
}


setTimeout(
    () => {
        autoReconnectFromMongoDB();
    },
    3000
);


// =====================================================
// PROCESS EXIT
// =====================================================

process.on(
    'exit',
    () => {
        activeSockets.forEach(
            (
                socket,
                number
            ) => {
                try {
                    socket.ws.close();
                } catch (_) {}

                activeSockets.delete(
                    number
                );

                socketCreationTime.delete(
                    number
                );
            }
        );


        const sessionDir =
            path.join(
                __dirname,
                'session'
            );


        if (
            fs.existsSync(
                sessionDir
            )
        ) {
            fs.emptyDirSync(
                sessionDir
            );
        }
    }
);


// =====================================================
// UNCaught EXCEPTION
// =====================================================

process.on(
    'uncaughtException',
    err => {
        noxLog(
            `Uncaught exception: ${err.message}`,
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
            reason &&
            reason.message
                ? reason.message
                : String(
                    reason
                );


        if (
            message.includes(
                'SessionError'
            ) ||
            message.includes(
                'into the future'
            ) ||
            message.includes(
                'decryptWithSessions'
            )
        ) {
            return;
        }


        noxLog(
            `Unhandled rejection: ${message}`,
            'error'
        );
    }
);


module.exports =
    router;
