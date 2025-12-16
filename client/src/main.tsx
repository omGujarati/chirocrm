import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import "./lib/debugUtils";

createRoot(document.getElementById("root")!).render(<App />);
