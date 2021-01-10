package javagm;

import java.security.*;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread) //Thread: 该状态为每个线程独享。
public class SM2UtilBenchmark {

    @State(Scope.Thread)
    public static class BenchmarkState {
        static int randomData = 128;
        static byte[] message = RandomStringUtils.random(randomData).getBytes();
        SM2Util instance;
        KeyPair keyPair;
        PublicKey pubKey;
        PrivateKey privKey;
        byte[] signbyte;
        byte[] encrypted;
        {
            try {
                instance = new SM2Util();
                keyPair = instance.generatekeyPair();
                pubKey = keyPair.getPublic();
                privKey = keyPair.getPrivate();
                signbyte = instance.sign(this.privKey, message);
                encrypted = instance.encrypt(this.pubKey, message);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Benchmark
    public void sign(BenchmarkState state) {
        try {
            state.instance.sign(state.privKey, state.message);
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    @Benchmark
    public void verify(BenchmarkState state) {
        try {
            state.instance.verify(state.pubKey, state.message, state.signbyte);
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    @Benchmark
    public void encrypt(BenchmarkState state) {
        try {
            state.instance.encrypt(state.pubKey, state.message);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    @Benchmark
    public void decrypt(BenchmarkState state) {
        try {
            state.instance.decrypt(state.privKey, state.encrypted);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(SM2UtilBenchmark.class.getSimpleName()) //benchmark 所在的类的名字，注意这里是使用正则表达式对所有类进行匹配的
                .forks(1) //进行 fork 的次数。如果 fork 数是2的话，则 JMH 会 fork 出两个进程来进行测试
                .warmupIterations(3) //预热的迭代次数
                .measurementIterations(5) //实际测量的迭代次数
                .build();

        new Runner(opt).run();
    }
}
