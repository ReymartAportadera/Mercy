// Theme Management — Dark Mode Only
const ThemeManager = {
    init: function() {
        // Always force dark mode
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('trustfile_theme', 'dark');
        document.body.style.backgroundColor = '#050505';
        document.body.style.backgroundImage = 'radial-gradient(circle at 50% 50%, #1a0505 0%, #050505 100%)';
    },

    // Kept for backward compatibility — does nothing
    setTheme: function() {},
    toggleTheme: function() {}
};

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    ThemeManager.init();
});

// Make available globally
window.ThemeManager = ThemeManager;