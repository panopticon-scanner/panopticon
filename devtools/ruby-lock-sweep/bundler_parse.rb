# Reads JSON lines {"id":..,"lock":..} on stdin; prints {"id":..,"ok":bool,"err":..} per line.
# Offline: parses lock TEXT with Bundler::LockfileParser only. Nothing is installed or fetched.
require "json"
require "bundler"
STDOUT.sync = true
STDIN.each_line do |line|
  job = JSON.parse(line)
  begin
    parser = Bundler::LockfileParser.new(job["lock"])
    specs = parser.specs.map { |s| [s.name, s.version.to_s, s.platform.to_s, s.source.class.name.split("::").last] }
    puts JSON.generate("id" => job["id"], "ok" => true, "specs" => specs)
  rescue Exception => e # rubocop:disable Lint/RescueException
    puts JSON.generate("id" => job["id"], "ok" => false, "err" => "#{e.class}: #{e.message}"[0, 160])
  end
end
