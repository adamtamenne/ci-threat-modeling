#!/usr/bin/env python3
"""
STRIDE threat model for a web application.

Defines the application's components, data flows, trust boundaries,
and data assets. pytm generates threats automatically based on the
architecture using STRIDE classification.

Run directly:  python threat-model/webapp.py --report threat-model/report.md
Run in CI:     see .github/workflows/threat-model.yml
"""

from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Data

# --- Threat Model definition ---
tm = TM("Web Application Threat Model")
tm.description = "STRIDE analysis of a web application with authentication, database, and external API integrations"
tm.isOrdered = True

# --- Data assets ---
user_credentials = Data("User Credentials", isPII=True, isCredentials=True)
session_token = Data("Session Token", isCredentials=True)
financial_data = Data("Financial Data", isPII=True)
api_response = Data("External API Response")

# --- Trust boundaries ---
internet = Boundary("Internet")
dmz = Boundary("DMZ / Load Balancer")
app_tier = Boundary("Application Tier")
data_tier = Boundary("Data Tier")
external = Boundary("External Services")

# --- Actors ---
user = Actor("End User")
user.inBoundary = internet

attacker = Actor("Attacker")
attacker.inBoundary = internet

# --- Components ---
lb = Server("Load Balancer / WAF")
lb.inBoundary = dmz
lb.protocol = "HTTPS"
lb.isEncrypted = True

web_app = Server("Web Application (ASP.NET Core)")
web_app.inBoundary = app_tier
web_app.protocol = "HTTPS"
web_app.isEncrypted = True
web_app.sanitizesInput = True
web_app.encodesOutput = True
web_app.hasAccessControl = True
web_app.authorizesSource = True

auth_service = Server("Authentication Service")
auth_service.inBoundary = app_tier
auth_service.protocol = "HTTPS"
auth_service.isEncrypted = True
auth_service.hasAccessControl = True

database = Datastore("Application Database")
database.inBoundary = data_tier
database.isEncrypted = True
database.hasAccessControl = True
database.isSql = True

cache = Datastore("Session Cache (Redis)")
cache.inBoundary = data_tier
cache.isEncrypted = False
cache.hasAccessControl = True

external_api = Server("External API")
external_api.inBoundary = external
external_api.protocol = "HTTPS"
external_api.isEncrypted = True

# --- Data flows ---
user_to_lb = Dataflow(user, lb, "User HTTPS Request")
user_to_lb.protocol = "HTTPS"
user_to_lb.isEncrypted = True
user_to_lb.data = [user_credentials, financial_data]

lb_to_app = Dataflow(lb, web_app, "Forwarded Request")
lb_to_app.protocol = "HTTPS"
lb_to_app.isEncrypted = True

app_to_auth = Dataflow(web_app, auth_service, "Auth Request")
app_to_auth.protocol = "HTTPS"
app_to_auth.isEncrypted = True
app_to_auth.data = [user_credentials]

auth_to_app = Dataflow(auth_service, web_app, "Auth Response (JWT)")
auth_to_app.protocol = "HTTPS"
auth_to_app.isEncrypted = True
auth_to_app.data = [session_token]

app_to_db = Dataflow(web_app, database, "Database Query")
app_to_db.protocol = "TCP"
app_to_db.isEncrypted = True
app_to_db.data = [financial_data]

db_to_app = Dataflow(database, web_app, "Query Result")
db_to_app.protocol = "TCP"
db_to_app.isEncrypted = True
db_to_app.data = [financial_data]

app_to_cache = Dataflow(web_app, cache, "Session Store/Retrieve")
app_to_cache.protocol = "TCP"
app_to_cache.isEncrypted = False
app_to_cache.data = [session_token]

app_to_external = Dataflow(web_app, external_api, "External API Call")
app_to_external.protocol = "HTTPS"
app_to_external.isEncrypted = True
app_to_external.data = [api_response]

external_to_app = Dataflow(external_api, web_app, "External API Response")
external_to_app.protocol = "HTTPS"
external_to_app.isEncrypted = True
external_to_app.data = [api_response]

if __name__ == "__main__":
    tm.process()

message_queue = Datastore("Message Queue (RabbitMQ)")
message_queue.inBoundary = app_tier
message_queue.isEncrypted = False
message_queue.hasAccessControl = False

app_to_queue = Dataflow(web_app, message_queue, "Publish Event")
app_to_queue.protocol = "AMQP"
app_to_queue.isEncrypted = False
app_to_queue.data = [financial_data]
