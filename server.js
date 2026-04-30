const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'x-auth-token'] }));
app.use(express.json());

// ============ DATABASES ============
const users = [];
const projects = [];
const tasks = [];
let nextUserId = 1, nextProjectId = 1, nextTaskId = 1;

// Designations available
const DESIGNATIONS = ['Admin', 'Intern', 'Developer', 'Tester', 'Designer', 'Manager', 'Senior', 'Employee', 'Trainer', 'HR', 'Fresher', 'Team Lead', 'Architect', 'Consultant'];

// ============ AUTH ============
app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password, role, designation } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (users.find(u => u.email === email)) return res.status(400).json({ error: 'User exists' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { 
        id: nextUserId++, 
        name, 
        email, 
        password: hashedPassword, 
        role: role || 'Member', 
        designation: designation || 'Employee' 
    };
    users.push(newUser);
    
    const token = jwt.sign({ id: newUser.id, role: newUser.role }, 'secret123', { expiresIn: '7d' });
    res.json({ token, user: { id: newUser.id, name, email, role: newUser.role, designation: newUser.designation } });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id, role: user.role }, 'secret123', { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, designation: user.designation } });
});

// ============ USERS - Get all users for assignment ============
app.get('/api/users', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        jwt.verify(token, 'secret123');
        // Return all users with their details
        res.json(users.map(u => ({ 
            id: u.id, 
            name: u.name, 
            email: u.email, 
            role: u.role, 
            designation: u.designation 
        })));
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/api/designations', (req, res) => {
    res.json(DESIGNATIONS);
});

// ============ PROJECTS ============
app.post('/api/projects', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, 'secret123');
        if (decoded.role !== 'Admin') return res.status(403).json({ error: 'Admin only' });
        
        const { name, description, teamMembers, startDate, endDate } = req.body;
        const project = { 
            id: nextProjectId++, 
            name, 
            description, 
            teamMembers: teamMembers || [], 
            startDate: startDate || null,
            endDate: endDate || null,
            createdBy: decoded.id, 
            createdAt: new Date() 
        };
        projects.push(project);
        res.json(project);
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/api/projects', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, 'secret123');
        let userProjects = projects;
        if (decoded.role !== 'Admin') {
            userProjects = projects.filter(p => p.teamMembers.includes(decoded.id) || p.createdBy === decoded.id);
        }
        // Add team member names to projects
        userProjects = userProjects.map(p => ({
            ...p,
            teamMemberNames: (p.teamMembers || []).map(memberId => {
                const member = users.find(u => u.id === memberId);
                return member ? { id: member.id, name: member.name, designation: member.designation } : null;
            }).filter(m => m)
        }));
        res.json(userProjects);
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.put('/api/projects/:id/add-member', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, 'secret123');
        if (decoded.role !== 'Admin') return res.status(403).json({ error: 'Admin only' });
        
        const project = projects.find(p => p.id === parseInt(req.params.id));
        if (!project) return res.status(404).json({ error: 'Project not found' });
        
        const { userId } = req.body;
        if (!project.teamMembers.includes(userId)) {
            project.teamMembers.push(userId);
        }
        res.json(project);
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// ============ TASKS ============
app.post('/api/tasks', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, 'secret123');
        const { title, description, projectId, assignedTo, dueDate } = req.body;
        
        const project = projects.find(p => p.id === projectId);
        if (!project) return res.status(404).json({ error: 'Project not found' });
        
        let status = 'Pending';
        if (dueDate) {
            const today = new Date();
            const due = new Date(dueDate);
            if (due < today) status = 'Overdue';
        }
        
        const task = { 
            id: nextTaskId++, 
            title, 
            description, 
            projectId, 
            assignedTo: assignedTo || null,
            dueDate: dueDate || null, 
            status, 
            createdBy: decoded.id, 
            createdAt: new Date()
        };
        tasks.push(task);
        res.json(task);
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/api/tasks', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, 'secret123');
        let userTasks = tasks;
        if (decoded.role !== 'Admin') {
            userTasks = tasks.filter(t => t.assignedTo === decoded.id || t.createdBy === decoded.id);
        }
        
        userTasks = userTasks.map(t => {
            const project = projects.find(p => p.id === t.projectId);
            const assignee = t.assignedTo ? users.find(u => u.id === t.assignedTo) : null;
            
            let status = t.status;
            if (t.dueDate && t.status !== 'Completed') {
                const today = new Date();
                const due = new Date(t.dueDate);
                if (due < today) status = 'Overdue';
                else status = t.status;
            }
            
            return { 
                ...t, 
                projectName: project ? project.name : 'Unknown',
                assigneeName: assignee ? assignee.name : 'Unassigned',
                assigneeDesignation: assignee ? assignee.designation : '',
                status: status
            };
        });
        res.json(userTasks);
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.put('/api/tasks/:id/status', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, 'secret123');
        const task = tasks.find(t => t.id === parseInt(req.params.id));
        if (!task) return res.status(404).json({ error: 'Task not found' });
        
        const { status } = req.body;
        task.status = status;
        res.json(task);
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.delete('/api/tasks/:id', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, 'secret123');
        const taskIndex = tasks.findIndex(t => t.id === parseInt(req.params.id));
        if (taskIndex === -1) return res.status(404).json({ error: 'Task not found' });
        
        const task = tasks[taskIndex];
        if (decoded.role !== 'Admin' && task.createdBy !== decoded.id) {
            return res.status(403).json({ error: 'Only Admin or Task Creator can delete' });
        }
        
        tasks.splice(taskIndex, 1);
        res.json({ message: 'Task deleted' });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// ============ DASHBOARD STATS ============
app.get('/api/dashboard/stats', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, 'secret123');
        let userTasks = tasks;
        if (decoded.role !== 'Admin') {
            userTasks = tasks.filter(t => t.assignedTo === decoded.id || t.createdBy === decoded.id);
        }
        
        const now = new Date();
        const stats = {
            totalTasks: userTasks.length,
            pendingTasks: userTasks.filter(t => t.status === 'Pending').length,
            inProgressTasks: userTasks.filter(t => t.status === 'In Progress').length,
            completedTasks: userTasks.filter(t => t.status === 'Completed').length,
            overdueTasks: userTasks.filter(t => t.dueDate && new Date(t.dueDate) < now && t.status !== 'Completed').length
        };
        res.json(stats);
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/', (req, res) => {
    res.json({ message: 'Team Task Manager API is running!' });
});

const PORT = 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`Designations: ${DESIGNATIONS.join(', ')}`);
});