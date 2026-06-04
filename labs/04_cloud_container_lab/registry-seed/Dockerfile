FROM docker:24-cli
COPY seed.sh /seed.sh
COPY corp-app/ /seed/corp-app/
COPY backup-tool/ /seed/backup-tool/
RUN chmod +x /seed.sh
CMD ["/seed.sh"]
