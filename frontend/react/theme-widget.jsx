const rootNodes = document.querySelectorAll("[data-react-theme-widget]");

function HudWidget() {
  return React.createElement(
    "div",
    { className: "cyber-hud-pill", "aria-hidden": "true" },
    React.createElement("span", { className: "cyber-hud-dot" }),
    React.createElement("span", null, "Threat Shield Active")
  );
}

rootNodes.forEach((node) => {
  if (!node) return;
  const root = ReactDOM.createRoot(node);
  root.render(React.createElement(HudWidget));
});
