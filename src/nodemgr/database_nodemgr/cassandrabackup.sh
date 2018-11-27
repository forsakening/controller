DIR=/var/lib/cassandra
PREFIX=cassandra_backup_
cleanup()
{
    find /var/lib/cassandra/  -maxdepth 1 -type f -name cassandra_backup_\*.* -mtime +7 -print0 | xargs -0 -r rm -f
}
cd $DIR
tar zcvf ${PREFIX}`date +%Y%m%d-%H%M%S`.tar.gz ./data --exclude ContrailAnalyticsCql
cleanup
