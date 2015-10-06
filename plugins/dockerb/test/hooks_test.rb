require_relative 'test_helper'

describe "env hooks" do
  let(:stage) { stages(:test_staging) }

  describe :after_deploy_setup do
    def fire
      Samson::Hooks.fire(:after_deploy_setup, "repo", stage, StringIO.new, 'abc')
    end

    around { |test| Dir.mktmpdir { |dir| Dir.chdir(dir) { test.call } } }

    before do
      FileUtils.mkdir("repo")
      File.write("repo/Dockerfile.erb", '<%= 1111 %>')
    end

    it "generates a Dockerfile" do
      fire
      File.read('repo/Dockerfile').must_equal "# Generated by dockerb #{Dockerb::VERSION}, do not modify\n1111\n# Generated by dockerb #{Dockerb::VERSION}, do not modify\n"
    end

    it "does nothing when Dockerfile exists" do
      File.write("repo/Dockerfile", '222')
      fire
      File.read('repo/Dockerfile').must_equal "222"
    end

    it "does not report to airbrake when it fails" do
      File.write("repo/Dockerfile.erb", '<% raise %>')
      assert_raises Samson::Hooks::UserError do
        fire
      end
    end
  end
end
