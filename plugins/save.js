const { cmd } = require('../nox');
const config = require('../config');

cmd({
    pattern: 'save',
    alias: [],
    react: '💾',
    desc: 'Save quoted Status photo/video to owner DM',
    category: 'media',
    filename: __filename
}, async (conn, mek, m, { from, reply, isOwner }) => {
    try {
        const quoted = m.quoted || mek.quoted;

        if (!quoted) {
            return reply(
                `❌ Reply to a Status photo or video with ${config.PREFIX || '.'}save`
            );
        }

        const messageType = quoted.mtype || quoted.messageType;

        if (
            messageType !== 'imageMessage' &&
            messageType !== 'videoMessage'
        ) {
            return reply('❌ Only Status photos and videos can be saved.');
        }

        const media = await quoted.download();

        if (!media) {
            return reply('❌ Failed to download the Status media.');
        }

        // Get the bot owner / sender JID.
        // When the owner uses .save, this is the owner's private DM.
        const ownerJid = mek.sender || m.sender;

        if (!ownerJid) {
            return reply('❌ Could not determine the owner DM.');
        }

        if (messageType === 'imageMessage') {
            await conn.sendMessage(
                ownerJid,
                {
                    image: media,
                    caption: quoted.text || '💾 Saved Status'
                }
            );
        }

        if (messageType === 'videoMessage') {
            await conn.sendMessage(
                ownerJid,
                {
                    video: media,
                    caption: quoted.text || '💾 Saved Status'
                }
            );
        }

        return reply('✅ Status saved to your DM.');

    } catch (error) {
        console.error('SAVE ERROR:', error);

        return reply(
            `❌ Failed to save Status: ${error?.message || error}`
        );
    }
});
