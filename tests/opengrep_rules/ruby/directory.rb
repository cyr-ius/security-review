# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# XPath, LDAP, NoSQL, regular expressions, logs, uploads and Dynamic LINQ.
class DirectoryController < ApplicationController
  def search
    name = params[:name]
    # ruleid: secreview.ruby.taint-xpath-injection
    @doc.xpath("//user[@name='#{name}']")
    # ok: secreview.ruby.taint-xpath-injection
    @doc.xpath("//user[@id='#{name.to_i}']")
    # ruleid: secreview.ruby.taint-ldap-injection
    ldap.search(base: "ou=people", filter: Net::LDAP::Filter.construct("(uid=#{name})"))
    # ok: secreview.ruby.taint-ldap-injection
    ldap.search(base: "ou=people", filter: Net::LDAP::Filter.equals("uid", name))
    # ruleid: secreview.ruby.taint-regex-injection
    pattern = Regexp.new(name)
    # ok: secreview.ruby.taint-regex-injection
    pattern = Regexp.new(Regexp.escape(name))
    # ruleid: secreview.ruby.taint-log-injection
    Rails.logger.info("search for #{name}")
    # ok: secreview.ruby.taint-log-injection
    Rails.logger.info("search for #{name.gsub(/[\r\n]/, ' ')}")
  end
end

def extract(zip_file, target)
  zip_file.each do |entry|
    # ruleid: secreview.ruby.zip-slip
    path = File.join(target, entry.name)
    entry.extract(path)
  end
end

def extract_safely(zip_file, target)
  zip_file.each do |entry|
    # ok: secreview.ruby.zip-slip
    path = File.expand_path(entry.name, target)
    raise "zip slip" unless path.start_with?(File.expand_path(target) + File::SEPARATOR)
    entry.extract(path)
  end
end
