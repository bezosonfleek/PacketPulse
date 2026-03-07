# ──────────────────────────────────────────────────────────────
#  PacketPulse — Frontend Dockerfile
#
#  This is a single-stage build using the official Nginx image.
#  nginx:alpine is used because:
#    - alpine = Alpine Linux, an extremely minimal Linux distro
#    - The image is only ~40MB vs ~190MB for nginx:latest
#    - No Python, no build tools, just Nginx
#
#  What happens:
#  1. Start from the nginx:alpine base image
#  2. Remove the default Nginx config
#  3. Copy our custom nginx.conf
#  4. Copy all frontend static files into the directory
#     Nginx serves files from by default
#
#  That's it. No build step needed — our frontend is plain
#  HTML/CSS/JS with no bundler (no webpack, no npm build).
#  This keeps the image tiny and the build fast.
# ──────────────────────────────────────────────────────────────

FROM nginx:alpine

# Remove the default Nginx config that comes with the image
# If we don't do this, Nginx would use its default config
# instead of ours, and the /api/ proxy wouldn't work
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom Nginx config into place
COPY nginx.conf /etc/nginx/conf.d/packetpulse.conf

# Copy all frontend files into Nginx's serving directory
# The . means "everything in the build context" (the frontend/ folder)
# Nginx serves files from /usr/share/nginx/html by default
COPY . /usr/share/nginx/html/

# Document that this container serves on port 80
EXPOSE 80
