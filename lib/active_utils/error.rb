module ActiveUtils #:nodoc:
  class HTTPRequestError < StandardError #:nodoc:
  end

  ActiveUtilsError = HTTPRequestError #:nodoc:

  class ConnectionError < HTTPRequestError # :nodoc:
  end

  class RetriableConnectionError < ConnectionError # :nodoc:
  end

  class ResponseError < HTTPRequestError # :nodoc:
    attr_reader :response

    def initialize(response, message = nil)
      @response = response
      @message  = message
    end

    def to_s
      code = response.try(:status) || response.try(:code)
      "Failed with #{code} #{response.message if response.respond_to?(:message)}"
    end
  end

  class ClientCertificateError < HTTPRequestError # :nodoc
  end

  class InvalidResponseError < HTTPRequestError # :nodoc
  end
end
