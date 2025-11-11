const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
  ? 'http://localhost:3000' 
  : `http://${window.location.hostname}:3000`;

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('loginForm');
  const errorBox = document.getElementById('errorBox');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBox.classList.add('d-none');
    const data = Object.fromEntries(new FormData(form).entries());
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Giriş başarısız' }));
        errorBox.textContent = err.error || 'Giriş başarısız';
        errorBox.classList.remove('d-none');
        return;
      }
      const { token } = await res.json();
      localStorage.setItem('token', token);
      window.location.replace('index.html');
    } catch (err) {
      errorBox.textContent = err.message || 'Bağlantı hatası';
      errorBox.classList.remove('d-none');
    }
  });
});


