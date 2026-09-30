import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App';
import './styles.css';
import './figma.css';
import './locked.css';
createRoot(document.getElementById('root')!).render(<StrictMode><App/></StrictMode>);
