import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./app/App";
import { EcpShell } from "./app/EcpShell";
import "./styles/global.css";
import "./styles/polish.css";
import "./styles/interaction.css";
import "./styles/themes.css";
import "./shared/ecpTokens.css";
import {initializeAppearance} from './app/appearance';
initializeAppearance();
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <EcpShell><App /></EcpShell>
    </BrowserRouter>
  </React.StrictMode>,
);
