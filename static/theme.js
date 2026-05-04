// Theme Management
const ThemeManager = {
    themes: {
        dark: { name: 'Dark Mode', icon: 'fa-moon' },
        light: { name: 'Light Mode', icon: 'fa-sun' }
    },
    
    currentTheme: 'dark',
    
    init: function() {
        const savedTheme = localStorage.getItem('trustfile_theme') || 'dark';
        this.setTheme(savedTheme);
        
        window.addEventListener('storage', (e) => {
            if (e.key === 'trustfile_theme') {
                this.setTheme(e.newValue);
            }
        });
    },
    
    setTheme: function(theme) {
        if (!this.themes[theme]) return;
        
        this.currentTheme = theme;
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('trustfile_theme', theme);
        
        // Update body background
        if (theme === 'light') {
            document.body.style.backgroundColor = '#f5f5f5';
            document.body.style.backgroundImage = 'radial-gradient(circle at 50% 50%, #ffffff 0%, #f0f0f0 100%)';
        } else {
            document.body.style.backgroundColor = '#050505';
            document.body.style.backgroundImage = 'radial-gradient(circle at 50% 50%, #1a0505 0%, #050505 100%)';
        }
        
        // Update all theme toggle buttons
        document.querySelectorAll('.theme-toggle-btn').forEach(btn => {
            const icon = btn.querySelector('i');
            if (icon) {
                icon.className = `fas ${this.themes[theme].icon}`;
            }
        });
        
        window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: theme } }));
    },
    
    toggleTheme: function() {
        const newTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
        
        // Save to server
        fetch('/api/save_theme', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ theme: newTheme })
        }).catch(error => console.error('Error saving theme:', error));
        
        return newTheme;
    }
};

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    ThemeManager.init();
});

// Make available globally
window.ThemeManager = ThemeManager;