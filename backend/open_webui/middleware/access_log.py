"""
Custom Access Logging Middleware per Open WebUI
Soluzione che FUNZIONA - bypassa completamente il logging di Uvicorn
"""

import uuid
import logging
import time
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class AccessLogMiddleware(BaseHTTPMiddleware):
    """
    Middleware che logga TUTTE le richieste con user_id e session_id
    Bypassa completamente il logging di Uvicorn
    """
    
    def __init__(self, app, logger_name: str = "open_webui.access", exclude_paths: list = None):
        super().__init__(app)
        self.logger = logging.getLogger(logger_name)
        # Percorsi da escludere dal logging (es. health checks)
        self.exclude_paths = exclude_paths or ["/health", "/api/health"]
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Salta logging per percorsi esclusi (opzionale)
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        # Genera o recupera session_id
        session_id = self._get_session_id(request)
        
        # Estrai user_id dall'autenticazione
        user_id = await self._get_user_id(request)
        
        # Timestamp inizio
        start_time = time.time()
        
        # Esegui la richiesta
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            # Log anche in caso di eccezione
            process_time = time.time() - start_time
            self.logger.error(
                f"email={user_id} | session_id={session_id[:8]} | "
                f"{request.client.host}:{request.client.port} - "
                f'"{request.method} {request.url.path}" EXCEPTION - '
                f"{str(e)[:100]} | time={process_time:.3f}s"
            )
            raise
        
        # Calcola tempo di elaborazione
        process_time = time.time() - start_time
        
        # Log della richiesta completata con TUTTI i dettagli
        # Usa solo primi 8 caratteri del session_id per leggibilità
        self.logger.info(
            f"email={user_id} | session_id={session_id[:8]} | "
            f"{request.client.host}:{request.client.port} - "
            f'"{request.method} {request.url.path}" {status_code} | '
            f"time={process_time:.3f}s"
        )
        
        # Aggiungi header alla risposta (opzionale)
        response.headers["X-Session-ID"] = session_id
        
        return response
    
    def _get_session_id(self, request: Request) -> str:
        """
        Recupera o genera un session_id
        La session_id dovrebbe essere persistente per tutta la sessione dell'utente
        """
        # PRIORITÀ 1: Cookie 'session_id' (più persistente)
        session_id = request.cookies.get("session_id")
        if session_id:
            return session_id
        
        # PRIORITÀ 2: Cookie 'token' (JWT token come session ID)
        # Il JWT token è più affidabile come identificatore di sessione
        # perché Open WebUI lo usa per l'autenticazione
        token = request.cookies.get("token")
        if token:
            # Usa l'hash del token come session_id per privacy
            import hashlib
            return hashlib.md5(token.encode()).hexdigest()[:16]
        
        # PRIORITÀ 3: Header 'X-Session-ID'
        session_id = request.headers.get("X-Session-ID")
        if session_id:
            return session_id
        
        # PRIORITÀ 4: Combinazione IP + User-Agent come identificatore temporaneo
        # Questo aiuta a mantenere la stessa session_id per utenti non autenticati
        # finché usano lo stesso browser dallo stesso IP
        try:
            user_agent = request.headers.get("user-agent", "")
            client_ip = request.client.host
            composite = f"{client_ip}:{user_agent}"
            import hashlib
            return hashlib.md5(composite.encode()).hexdigest()[:16]
        except:
            pass
        
        # FALLBACK: Genera nuovo UUID
        # Questo dovrebbe accadere raramente
        return str(uuid.uuid4())[:16]
    
    async def _get_user_id(self, request: Request) -> str:
        """Estrae email (o user_id come fallback) dalla richiesta"""
        try:
            # Metodo 1: request.state.user (dopo autenticazione)
            if hasattr(request.state, "user") and request.state.user:
                user = request.state.user
                if isinstance(user, dict):
                    # PRIORITÀ: email > username > id
                    email = user.get("email")
                    if email:
                        return str(email)
                    username = user.get("username")
                    if username:
                        return str(username)
                    user_id = user.get("id")
                    if user_id:
                        return str(user_id)
                elif hasattr(user, "email"):
                    return str(user.email)
                elif hasattr(user, "username"):
                    return str(user.username)
                elif hasattr(user, "id"):
                    return str(user.id)
            
            # Metodo 2: JWT token nei cookies - estrai l'email
            token = request.cookies.get("token")
            if token:
                try:
                    import jwt
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    # PRIORITÀ: email > username > sub > user_id > id
                    email = (
                        decoded.get("email") or
                        decoded.get("username") or 
                        decoded.get("sub") or 
                        decoded.get("user_id") or
                        decoded.get("id")
                    )
                    if email:
                        return str(email)
                except Exception as e:
                    # Log del token decodificato per debug
                    import logging
                    logger = logging.getLogger("open_webui.access")
                    logger.debug(f"Errore decodifica JWT: {e}")
        
        except Exception as e:
            import logging
            logger = logging.getLogger("open_webui.access")
            logger.debug(f"Errore estrazione user: {e}")
        
        return "anonymous"


def setup_access_logging(app, log_level: str = "INFO", exclude_paths: list = None):
    """
    Setup del logging per l'applicazione
    Da chiamare in main.py DOPO aver creato l'app FastAPI
    
    Args:
        app: FastAPI application
        log_level: Livello di logging (INFO, DEBUG, WARNING, ERROR)
        exclude_paths: Lista di percorsi da escludere dal logging (es. ["/health"])
    """
    # Crea logger personalizzato
    logger = logging.getLogger("open_webui.access")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Handler per stdout
    handler = logging.StreamHandler()
    handler.setLevel(getattr(logging, log_level.upper()))
    
    # Formato semplice e leggibile
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.propagate = False
    
    # Aggiungi il middleware all'app con percorsi da escludere
    if exclude_paths is None:
        exclude_paths = ["/health", "/api/health"]
    
    app.add_middleware(AccessLogMiddleware, exclude_paths=exclude_paths)
    
    # DISABILITA il logging di Uvicorn per evitare duplicati
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").propagate = False
    
    logger.info(f"Custom access logging attivato - Percorsi esclusi: {exclude_paths}")

