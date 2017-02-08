# frozen_string_literal: true
# TODO: should check based on docker_repo_digest not tag
# TODO: should show output for scans of external builds (without job)
module SamsonHyperclair
  class Engine < Rails::Engine
  end

  class << self
    def append_build_job_with_scan(build)
      return unless clair = ENV['HYPERCLAIR_PATH']
      job = build.docker_build_job

      append_output job, "### Clair scan: started\n"

      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          sleep 0.1 if Rails.env.test? # in test we reuse the same connection, so we cannot use it at the same time
          success, output, time = scan(clair, build.project, build.docker_tag)
          status = (success ? "success" : "errored or vulnerabilities found")
          output = "### Clair scan: #{status} in #{time}s\n#{output}"
          append_output job, output
        end
      end
    end

    private

    def append_output(job, output)
      return unless job # external builds have no job ... so we cannot show any output
      job.reload
      job.update_column(:output, job.output + output)
    end

    def scan(executable, project, docker_tag)
      registry = DockerRegistry.first
      with_time do
        Samson::CommandExecutor.execute(
          executable,
          *project.docker_repo(registry).split('/', 2),
          docker_tag,
          env: {
            'DOCKER_REGISTRY_USER' => registry.username,
            'DOCKER_REGISTRY_PASS' => registry.password
          },
          whitelist_env: [
            'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY',
            'PATH'
          ],
          timeout: 60 * 60
        )
      end
    end

    def with_time
      result = []
      time = Benchmark.realtime { result = yield }
      result << time
    end
  end
end

Samson::Hooks.callback :after_docker_build do |build|
  if build.docker_repo_digest
    SamsonHyperclair.append_build_job_with_scan(build)
  end
end
