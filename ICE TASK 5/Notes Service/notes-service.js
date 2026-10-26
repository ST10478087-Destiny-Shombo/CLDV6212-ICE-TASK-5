const express = require('express');
const { randomUUID } = require('crypto');

const app = express();
app.use(express.json());

/* ---------- MULTI-USER NOTES STORE ----------
 * Each note stores its ownerId so users only see their own notes.
 * Same shape as notes you built in Task 3, plus ownerId.
 */
const notes = [];

/* Trusted-header middleware (gateway already authenticated the caller) */
function requireUser(req, res, next) {
    const userId = req.headers['x-user-id'];
    if (!userId) return res.status(401).json({ error: 'No user context' });
    req.userId = userId;
    req.userRole = req.headers['x-user-role'] || 'user';
    next();
}
app.use('/notes', requireUser);

/* CREATE */
app.post('/notes', (req, res) => {
    const { title, content } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'title and content required' });

    const note = {
        id: randomUUID(),
        ownerId: req.userId,                 // <-- multi-user separation
        title,
        content,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
    };
    notes.push(note);
    res.status(201).json(note);
});

/* READ ALL (only the caller's notes; admins see everything) */
app.get('/notes', (req, res) => {
    const mine = req.userRole === 'admin'
        ? notes
        : notes.filter(n => n.ownerId === req.userId);
    res.json(mine);
});

/* READ ONE */
app.get('/notes/:id', (req, res) => {
    const note = notes.find(n => n.id === req.params.id);
    if (!note) return res.status(404).json({ error: 'Not found' });
    if (note.ownerId !== req.userId && req.userRole !== 'admin')
        return res.status(403).json({ error: 'Forbidden' });
    res.json(note);
});

/* UPDATE */
app.put('/notes/:id', (req, res) => {
    const note = notes.find(n => n.id === req.params.id);
    if (!note) return res.status(404).json({ error: 'Not found' });
    if (note.ownerId !== req.userId && req.userRole !== 'admin')
        return res.status(403).json({ error: 'Forbidden' });

    const { title, content } = req.body;
    if (title !== undefined) note.title = title;
    if (content !== undefined) note.content = content;
    note.updatedAt = new Date().toISOString();
    res.json(note);
});

/* DELETE */
app.delete('/notes/:id', (req, res) => {
    const idx = notes.findIndex(n => n.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    if (notes[idx].ownerId !== req.userId && req.userRole !== 'admin')
        return res.status(403).json({ error: 'Forbidden' });

    notes.splice(idx, 1);
    res.status(204).send();
});

app.listen(3001, () => console.log('Notes service on http://localhost:3001'));