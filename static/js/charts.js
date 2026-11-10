/* ==========================================================================
   Shared Chart.js theme helper — reads live CSS variables so charts match
   whichever theme (dark/light) is currently active.
   ========================================================================== */

function cyberChartTheme() {
  const styles = getComputedStyle(document.documentElement);
  const v = (name) => styles.getPropertyValue(name).trim();
  return {
    text: v("--text-muted"),
    grid: v("--border"),
    accent: v("--accent"),
    accent2: v("--accent-2"),
    success: v("--success"),
    warning: v("--warning"),
    danger: v("--danger"),
    critical: v("--critical"),
    surface: v("--surface"),
  };
}

function cyberChartDefaults() {
  const t = cyberChartTheme();
  return {
    plugins: {
      legend: { labels: { color: t.text, font: { size: 11 }, boxWidth: 10 } },
      tooltip: {
        backgroundColor: t.surface,
        titleColor: t.text,
        bodyColor: t.text,
        borderColor: t.grid,
        borderWidth: 1,
        padding: 10,
      },
    },
    maintainAspectRatio: false,
    responsive: true,
  };
}
