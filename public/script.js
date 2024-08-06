        const socket = io();
        let token = '';
        let currentChatUser = '';

        document.getElementById('loginButton').addEventListener('click', login);
        document.getElementById('registerButton').addEventListener('click', register);
        document.getElementById('refreshButton').addEventListener('click', refreshAll);
        document.getElementById('addImageButton').addEventListener('click', () => {
            document.getElementById('imageInput').click();
        });
        document.getElementById('imageInput').addEventListener('change', handleImagePreview);
        document.getElementById('removeImageButton').addEventListener('click', removeImagePreview);
        
        function handleImagePreview(event) {
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    document.getElementById('thumbnail').src = e.target.result;
                    document.getElementById('imagePreview').style.display = 'block';
                    document.getElementById('removeImageButton').style.display = 'block';
                };
                reader.readAsDataURL(file);
            }
        }

        function removeImagePreview() {
            document.getElementById('imageInput').value = '';
            document.getElementById('thumbnail').src = '';
            document.getElementById('imagePreview').style.display = 'none';
            document.getElementById('removeImageButton').style.display = 'none';
        }

        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (response.ok) {
                const data = await response.json();
                token = data.token;
                document.getElementById('login').classList.add('hidden');
                document.getElementById('chat').classList.remove('hidden');
                document.getElementById('currentUser').innerText = "Welcome, " + username;
                socket.emit('join', username);
                refreshAll();
                setInterval(refreshAll, 500); // Auto-refresh every 0.5 seconds
            } else {
                alert('Login failed');
            }
        }

        async function register() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (response.ok) {
                alert('User registered');
            } else {
                alert('Registration failed');
            }
        }

        async function refreshAll() {
            await loadUsers();
            if (currentChatUser) {
                await loadMessages(currentChatUser);
            }
        }

        async function loadUsers() {
            const response = await fetch('/users', {
                headers: { 'Authorization': token }
            });
            const users = await response.json();
            
            const unreadResponse = await fetch('/unread-messages', {
                headers: { 'Authorization': token }
            });
            const unreadMessages = await unreadResponse.json();
            const unreadCounts = unreadMessages.reduce((acc, { _id, count }) => {
                acc[_id] = count;
                return acc;
            }, {});

            const userList = document.getElementById('userList');
            userList.innerHTML = '';
            users.forEach(user => {
                const li = document.createElement('li');
                li.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center';
                li.innerText = user.username;
                li.addEventListener('click', () => loadMessages(user.username));
                
                // Add unread message count
                const unreadCount = unreadCounts[user.username] || 0;
                if (unreadCount > 0) {
                    const badge = document.createElement('span');
                    badge.className = 'badge badge-danger badge-pill';
                    badge.innerText = unreadCount;
                    li.appendChild(badge);
                }

                userList.appendChild(li);
            });
        }

        async function loadMessages(withUser) {
            currentChatUser = withUser;
            document.getElementById('chatUser').innerText = withUser;
            const response = await fetch(`/messages/${withUser}`, {
                headers: { 'Authorization': token }
            });
            const messages = await response.json();
            const messageList = document.getElementById('messageList');
            messageList.innerHTML = '';
            messages.forEach(message => {
                addMessage(message);
            });

            // Mark messages as read
            await fetch(`/messages/mark-read/${withUser}`, {
                method: 'POST',
                headers: { 'Authorization': token }
            });

            // Refresh user list to update unread counts
            loadUsers();
        }

        function addMessage(message) {
            const li = document.createElement('li');

            if (message.text) {
                li.innerText = `${message.from}: ${message.text}`;
            }

            if (message.imageUrl) {
                const img = document.createElement('img');
                img.src = message.imageUrl;
                img.alt = 'Image';
                img.style.marginTop = '2%';
                img.style.maxWidth = '50%';
                img.style.display = 'block';
                li.appendChild(img);
            }

            document.getElementById('messageList').appendChild(li);
        }


        document.getElementById('messageForm').addEventListener('submit', sendMessage);

        async function sendMessage(event) {
            event.preventDefault();
            const text = document.getElementById('messageInput').value;
            const imageInput = document.getElementById('imageInput');
            const imageFile = imageInput.files[0];

            const formData = new FormData();
            formData.append('to', currentChatUser);

            if (text.trim() !== '') {
                formData.append('text', text);
            }

            if (imageFile) {
                formData.append('image', imageFile);
            }

            const response = await fetch('/upload', {
                method: 'POST',
                headers: {
                    'Authorization': token
                },
                body: formData
            });

            if (response.ok) {
                const data = await response.json();
                addMessage({ from: 'You', text: data.text, imageUrl: data.filePath });
            } else {
                alert('Failed to send message');
            }

            document.getElementById('messageInput').value = '';
            imageInput.value = '';
            removeImagePreview();
        }

        socket.on('private message', (message) => {
            if (message.from === currentChatUser || message.to === currentChatUser) {
                const li = document.createElement('li');
                li.innerText = `${message.from}: ${message.text}`;
                document.getElementById('messageList').appendChild(li);
            }
        });

        socket.on('user connected', (username) => {
            console.log(`${username} has joined the chat`);
        });