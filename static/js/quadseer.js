/* QuadSeer v3.0 — Alpine.js Global Store & Utilities
 *
 * FIX: Replaced fragile document.querySelector('[x-data*=...]')._x_dataStack[0]
 * with proper Alpine.js $store pattern. All components use $store.toasts
 * for notifications instead of direct DOM access.
 */

document.addEventListener('alpine:init', () => {

    // Global Toast Store — accessible via $store.toasts from any component
    Alpine.store('toasts', {
        items: [],
        nextId: 1,

        add(message, type = 'info', duration = 4000) {
            const id = this.nextId++;
            const toast = { id, message, type, visible: true };
            this.items.push(toast);

            setTimeout(() => {
                this.remove(id);
            }, duration);
        },

        remove(id) {
            const idx = this.items.findIndex(t => t.id === id);
            if (idx !== -1) {
                this.items[idx].visible = false;
                setTimeout(() => {
                    this.items = this.items.filter(t => t.id !== id);
                }, 200);
            }
        }
    });

    // Global Auth Store
    Alpine.store('auth', {
        token: localStorage.getItem('token') || null,
        user: null,

        isAuthenticated() {
            return !!this.token;
        },

        setToken(token) {
            this.token = token;
            localStorage.setItem('token', token);
        },

        clear() {
            this.token = null;
            this.user = null;
            localStorage.removeItem('token');
        },

        async fetchUser() {
            if (!this.token) return;
            try {
                const res = await fetch('/api/v1/auth/me', {
                    headers: { 'Authorization': `Bearer ${this.token}` }
                });
                if (res.ok) {
                    this.user = await res.json();
                } else {
                    this.clear();
                }
            } catch (e) {
                console.error('Failed to fetch user:', e);
            }
        }
    });
});

// Global fetch interceptor for token injection
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    const token = localStorage.getItem('token');
    if (token && args[1] && !args[1].headers?.Authorization) {
        args[1].headers = {
            ...args[1].headers,
            'Authorization': `Bearer ${token}`
        };
    }
    return originalFetch.apply(this, args);
};
