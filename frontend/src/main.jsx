import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { ThemeProvider } from './store/ThemeContext';
import './styles.css';

createRoot(document.getElementById('root')).render(
  <BrowserRouter><ThemeProvider><App /></ThemeProvider></BrowserRouter>
);
